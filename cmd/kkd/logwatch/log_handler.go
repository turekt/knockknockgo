package logwatch

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/turekt/knockknockgo/cmd/kkd/fwrule"
	"github.com/turekt/knockknockgo/pkg/kcrypto"
	"github.com/turekt/knockknockgo/pkg/kdata"
	"github.com/turekt/knockknockgo/pkg/kprofile"
)

const fwOpRetry = 5

type LogHandler struct {
	ProfilesDir  string
	EventChannel chan string
	FWRuleType   fwrule.FWRuleType
}

func (lh *LogHandler) HandleLogEntry() {
	for event := range lh.EventChannel {
		kle := kdata.FromLogEntry(event)
		if kle.Dpt == 0 {
			continue
		}

		kp, err := kprofile.Deserialize(kle.Dpt, lh.ProfilesDir)
		if err != nil {
			log.Printf("failed to read profile for port %d %v", kle.Dpt, err)
			continue
		}

		kc, err := kcrypto.New(kp.Cipher, kp.Key, kp.NonceSalt)
		if err != nil {
			log.Printf("failed to init cipher for port %d %v", kle.Dpt, err)
			continue
		}

		encrypted, err := kc.Encrypt(kle.Dpt, uint16(kle.Nonce))
		if err != nil {
			log.Printf("failed to encrypt nonce %d for port %d %v", kp.NonceCounter, kle.Dpt, err)
			continue
		}

		if uint16(kle.Nonce) < kp.NonceCounter {
			log.Printf("nonces out of sync %d and %d", kp.NonceCounter, kle.Nonce)
			continue
		}

		kde := kdata.FromCipherText(encrypted)
		if kdata.Verify(kle, kde) {
			go func() {
				rule := fwrule.New(lh.FWRuleType, net.ParseIP(kle.Src), kle.Dpt)
				if err := lh.ruleOpWithRetry(fwOpRetry, rule.Apply); err != nil {
					log.Printf("failed to add rule %v", err)
					return
				}
				log.Printf("%s now has access on port %d\n", kle.Src, kle.Dpt)
				time.Sleep(time.Duration(kp.ConnWindow * uint(time.Second)))
				if err := lh.ruleOpWithRetry(fwOpRetry, rule.Drop); err != nil {
					log.Printf("failed to delete rule %v", err)
					return
				}
				log.Printf("%s no longer has access on port %d\n", kle.Src, kle.Dpt)
			}()

			if kp.NonceCounter != uint16(kle.Nonce) {
				kp.NonceCounter = uint16(kle.Nonce)
			} else {
				kp.NonceCounter++
			}
			kp.Serialize(lh.ProfilesDir)
		} else {
			log.Printf("dropping attempt on port %d", kle.Dpt)
		}
	}
	log.Printf("event channel closed")
}

func (lh *LogHandler) ruleOpWithRetry(retryCount int, op func() error) error {
	for i := 0; i < retryCount; i++ {
		if err := op(); err != nil {
			log.Printf("failed to execute op rule %d/%d %v", i+1, fwOpRetry, err)
			time.Sleep(time.Duration(1 * time.Second))
			if i == fwOpRetry-1 {
				return errors.New("fw op rule failed")
			}
			continue
		}
		break
	}
	return nil
}
