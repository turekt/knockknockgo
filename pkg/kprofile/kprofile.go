package kprofile

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/turekt/knockknockgo/pkg/kcrypto"
)

const (
	KnockProfilesDir                 = "/opt/kkgo/profiles"
	KnockProfilesDefaultNonceCounter = 1
)

type KnockProfile struct {
	Key          []byte                  `json:"key"`
	NonceSalt    []byte                  `json:"nsalt"`
	NonceCounter uint16                  `json:"counter"`
	Cipher       kcrypto.KnockCipherType `json:"cipher"`
	ConnWindow   uint                    `json:"connwin"`
	Port         uint16                  `json:"-"`
}

func NewKnockProfile(port uint16, connWindow uint, cipher kcrypto.KnockCipherType) (*KnockProfile, error) {
	key, err := kcrypto.GenerateRandomData(32)
	if err != nil {
		return nil, err
	}
	nsalt, err := kcrypto.GenerateRandomData(32)
	if err != nil {
		return nil, err
	}
	return &KnockProfile{
		Key:          key,
		NonceSalt:    nsalt,
		NonceCounter: 1,
		Cipher:       cipher,
		ConnWindow:   connWindow,
		Port:         port,
	}, nil
}

func (kp *KnockProfile) Serialize(folderPath string) error {
	os.MkdirAll(folderPath, 0755)

	b, err := json.MarshalIndent(kp, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(folderPath, strconv.Itoa(int(kp.Port))+".json"), b, 0644)
}

func Deserialize(port uint16, folderPath string) (*KnockProfile, error) {
	portStr := strconv.Itoa(int(port))
	b, err := ioutil.ReadFile(filepath.Join(folderPath, portStr+".json"))
	if err != nil {
		return nil, err
	}

	kp := new(KnockProfile)
	if err := json.Unmarshal(b, kp); err != nil {
		return kp, err
	}

	kp.Port = port
	return kp, err
}
