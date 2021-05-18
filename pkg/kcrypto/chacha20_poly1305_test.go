package kcrypto

import (
	"testing"
)

const (
	chachaKey       = "01234567890123456789012345678901"
	chachaNonceSalt = "noncesalttest2"
)

func TestChacha20DeriveNonce(t *testing.T) {
	kc := initChacha(t)
	deriveNonceTest(t, kc)
}

func TestEncrypt(t *testing.T) {
	kc := initChacha(t)
	encryptTest(t, kc)
}

func initChacha(t *testing.T) *KnockCipher {
	kc, err := newChacha20Poly1305Cipher([]byte(chachaKey), []byte(chachaNonceSalt))
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	return kc
}
