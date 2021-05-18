package logwatch

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	inotifyEventStructSize  = 0x10
	inotifyEventNameMaxSize = 0xff
	inotifyRerunFlags       = syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_MOVE | syscall.IN_DELETE
	inotifyReadFlags        = syscall.IN_CLOSE_WRITE | syscall.IN_MODIFY
)

type LogWatcher struct {
	Path         string
	EventChannel chan string
}

func (fwlw *LogWatcher) TailFile() {
	interrupt := make(chan byte)
	for {
		select {
		case <-interrupt:
			log.Printf("tail interrupt registered")
			close(fwlw.EventChannel)
			return
		default:
			if _, err := os.Stat(fwlw.Path); os.IsNotExist(err) {
				log.Printf("%s does not exist, retrying ...\n", fwlw.Path)
				time.Sleep(3 * time.Second)
				continue
			}

			fwlw.watch(interrupt)
		}
		time.Sleep(400 * time.Millisecond)
	}
}

func (fwlw *LogWatcher) watch(interrupt chan byte) {
	infd, err := syscall.InotifyInit1(0)
	if err != nil {
		log.Printf("failed inotify init1 with error %v", err)
		return
	}
	defer syscall.Close(infd)

	wdesc, err := syscall.InotifyAddWatch(infd, fwlw.Path, syscall.IN_IGNORED|inotifyReadFlags|inotifyRerunFlags)
	if err != nil {
		log.Printf("failed inotify add watch with error %v", err)
		return
	}
	fwlw.registerInterrupt(interrupt, infd, wdesc)
	defer syscall.InotifyRmWatch(infd, uint32(wdesc))

	buffer := make([]byte, inotifyEventStructSize+inotifyEventNameMaxSize+1)
	finfo, err := os.Stat(fwlw.Path)
	if err != nil {
		log.Printf("failed file stat %s %v", fwlw.Path, err)
	}
	var bytesRead int64 = finfo.Size()

	for {
		n, err := syscall.Read(infd, buffer)
		if err != nil {
			log.Printf("failed inotify read with error %v", err)
		}
		if n == 0 {
			continue
		}

		ie := syscall.InotifyEvent{}
		if err := binary.Read(bytes.NewBuffer(buffer), binary.LittleEndian, &ie); err != nil {
			log.Printf("failed inotify buffer read with error %v", err)
		}

		switch {
		case ie.Mask&inotifyRerunFlags != 0:
			log.Printf("watched file moved or deleted")
			return
		case ie.Mask&syscall.IN_IGNORED == syscall.IN_IGNORED:
			log.Printf("ignored signal received")
			return
		case ie.Mask&inotifyReadFlags != 0:
			finfo, err := os.Stat(fwlw.Path)
			if err != nil {
				log.Printf("failed file stat on IN_MODIFY %s %v", fwlw.Path, err)
			}

			if finfo.Size() <= bytesRead {
				bytesRead = 0
			}
			bytesRead += fwlw.readAndSendLog(bytesRead)
		}

		for i := uint32(0); i < ie.Len; i++ {
			buffer[inotifyEventStructSize+i] = 0
		}
	}
}

func (fwlw *LogWatcher) readAndSendLog(bytesRead int64) int64 {
	file, err := os.Open(fwlw.Path)
	if err != nil {
		log.Printf("failed to open %s %v", fwlw.Path, err)
		return 0
	}
	defer file.Close()

	if _, err := file.Seek(bytesRead, io.SeekStart); err != nil {
		log.Printf("seek failed %s %v", fwlw.Path, err)
		return 0
	}

	var n int64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fwlw.EventChannel <- line
		n += int64(len(line) + 1)
	}
	return n
}

func (fwlw *LogWatcher) registerInterrupt(interrupt chan byte, fd, wdesc int) {
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)
	go func() {
		<-sigchan
		log.Printf("catched interrupt")
		syscall.InotifyRmWatch(fd, uint32(wdesc))
		log.Printf("propagating interrupt")
		interrupt <- 1
	}()
}
