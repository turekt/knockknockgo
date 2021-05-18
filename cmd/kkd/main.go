package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"sync"

	"github.com/turekt/knockknockgo/cmd/kkd/fwrule"
	"github.com/turekt/knockknockgo/cmd/kkd/logwatch"
	"github.com/turekt/knockknockgo/pkg/kcrypto"
	"github.com/turekt/knockknockgo/pkg/kprofile"
	"golang.org/x/sys/unix"
)

const (
	kkdCmdRun      = "run"
	kkdCmdGenerate = "gen"
)

func generateProfile(port int, connWindow uint, cipher, profilesDir string) {
	if port < 0 || port > 0xffff {
		log.Fatalf("bad port %d", port)
	}

	cipherType := kcrypto.Chacha20Poly1305
	switch cipher {
	case "1", "aes", "aes-gcm":
		cipherType = kcrypto.AesGcm
	}

	kp, err := kprofile.NewKnockProfile(uint16(port), connWindow, cipherType)
	if err != nil {
		log.Fatalf("error creating profile %v", err)
	}

	if err := kp.Serialize(profilesDir); err != nil {
		log.Fatalf("error serializing profile %v", err)
	}

	b, err := json.MarshalIndent(kp, "", "  ")
	if err != nil {
		return
	}
	b64b := base64.StdEncoding.EncodeToString(b)
	fmt.Printf("execute this on client side:\necho '%s' | base64 -d > %s/%d.json\n", b64b, profilesDir, kp.Port)
}

func monitor(profilesDir, kernLog, firewallType string) {
	fw := fwrule.IptFWRuleType
	switch firewallType {
	case "nft", "n", "1":
		fw = fwrule.NftFWRuleType
	}

	wg := new(sync.WaitGroup)
	eventChannel := make(chan string)
	go func() {
		defer wg.Done()
		handler := &logwatch.LogHandler{
			ProfilesDir:  profilesDir,
			EventChannel: eventChannel,
			FWRuleType:   fw,
		}
		handler.HandleLogEntry()
	}()

	go func() {
		defer wg.Done()
		watcher := &logwatch.LogWatcher{
			Path:         kernLog,
			EventChannel: eventChannel,
		}
		watcher.TailFile()
	}()

	if err := dropPrivileges(); err != nil {
		log.Printf("error dropping privileges %v", err)
	}
	wg.Add(2)
	wg.Wait()
	log.Printf("exit")
}

func dropPrivileges() error {
	u, err := user.Lookup("nobody")
	if err != nil {
		return err
	}
	g, err := user.LookupGroup("adm")
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}

	if err := unix.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := unix.Setregid(-1, gid); err != nil {
		return err
	}
	if err := unix.Setreuid(-1, uid); err != nil {
		return err
	}

	return nil
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatalln("this program must be run as root")
	}

	if len(os.Args) < 2 {
		log.Fatalf("required one of subcommands: %s or %s", kkdCmdGenerate, kkdCmdRun)
	}

	switch os.Args[1] {
	case kkdCmdRun:
		runCmd := flag.NewFlagSet(kkdCmdRun, flag.ExitOnError)
		kernLog := runCmd.String("kernlog", "/var/log/kern.log", "Location where firewall logs are written")
		firewallType := runCmd.String("fw", "nft", "Firewall type: nftables (nft) or iptables (ipt)")
		profilesRunDir := runCmd.String("profiles", kprofile.KnockProfilesDir, "Location where port profiles are stored")
		runCmd.Parse(os.Args[2:])
		monitor(*profilesRunDir, *kernLog, *firewallType)
	case kkdCmdGenerate:
		genCmd := flag.NewFlagSet(kkdCmdGenerate, flag.ExitOnError)
		port := genCmd.Int("port", 22, "Specifies profile port when generating profile")
		connWindow := genCmd.Uint("connwin", 300, "Specifies number of seconds during which port will be available after successful knock")
		cipher := genCmd.String("cipher", "", "Specifies cipher algorithm when generating port profile")
		profilesGenDir := genCmd.String("profiles", kprofile.KnockProfilesDir, "Location where port profiles are stored")
		genCmd.Parse(os.Args[2:])
		generateProfile(*port, *connWindow, *cipher, *profilesGenDir)
	default:
		flag.PrintDefaults()
	}
}
