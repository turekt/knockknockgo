package kdata

import (
	"encoding/binary"
	"strconv"
	"strings"
)

const (
	KnockDataKeyId      = "ID"
	KnockDataKeyAck     = "ACK"
	KnockDataKeySeq     = "SEQ"
	KnockDataKeyWindow  = "WINDOW"
	KnockDataKeySrc     = "SRC"
	KnockDataKeyDpt     = "DPT"
	KnockDataKeySpt     = "SPT"
	KnockDataKeyFlowLbl = "FLOWLBL"
)

type KnockDataEntry struct {
	Spt    uint16
	Dpt    uint16
	Seq    uint32
	Ack    uint32
	Window uint16
	Src    string
	Nonce  uint16
}

func FromCipherText(ciphertext []byte) *KnockDataEntry {
	kde := new(KnockDataEntry)

	switch lenCt := len(ciphertext); {
	case lenCt > 13:
		kde.Spt = binary.BigEndian.Uint16(ciphertext[12:14])
		fallthrough
	case lenCt > 11:
		kde.Window = binary.BigEndian.Uint16(ciphertext[10:12])
		fallthrough
	case lenCt > 9:
		kde.Ack = binary.BigEndian.Uint32(ciphertext[6:10])
		fallthrough
	case lenCt > 5:
		kde.Seq = binary.BigEndian.Uint32(ciphertext[2:6])
		fallthrough
	case lenCt > 1:
		kde.Nonce = binary.BigEndian.Uint16(ciphertext[:2])
	}

	return kde
}

func FromLogEntry(line string) *KnockDataEntry {
	kle := new(KnockDataEntry)
	for _, parts := range strings.Split(line, " ") {
		elements := strings.Split(parts, "=")
		if len(elements) != 2 {
			continue
		}

		if elements[0] == KnockDataKeySrc {
			kle.Src = elements[1]
			continue
		}

		num, err := strconv.Atoi(elements[1])
		if err != nil {
			continue
		}

		switch elements[0] {
		case KnockDataKeyFlowLbl, KnockDataKeyId:
			kle.Nonce = uint16(num)
		case KnockDataKeyAck:
			kle.Ack = uint32(num)
		case KnockDataKeySeq:
			kle.Seq = uint32(num)
		case KnockDataKeyWindow:
			kle.Window = uint16(num)
		case KnockDataKeySpt:
			kle.Spt = uint16(num)
		case KnockDataKeyDpt:
			kle.Dpt = uint16(num)
		}
	}
	return kle
}

func Verify(kde1, kde2 *KnockDataEntry) bool {
	return kde1.Ack == kde2.Ack &&
		kde1.Nonce == kde2.Nonce &&
		kde1.Seq == kde2.Seq &&
		kde1.Spt == kde2.Spt &&
		kde1.Window == kde2.Window
}
