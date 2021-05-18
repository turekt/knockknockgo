package kcrypto

import (
	"testing"
)

const (
	aesKey       = "0123456789012345"
	aesNonceSalt = "noncesalttest1"
)

func TestAesDeriveNonce(t *testing.T) {
	kc := initAes(t)
	deriveNonceTest(t, kc)
}

func TestAesEncrypt(t *testing.T) {
	kc := initAes(t)
	encryptTest(t, kc)
}

func initAes(t *testing.T) *KnockCipher {
	kc, err := newAesGcmCipher([]byte(aesKey), []byte(aesNonceSalt))
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	return kc
}
