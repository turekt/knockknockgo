package kcrypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	Chacha20Poly1305 KnockCipherType = iota
	AesGcm
)

type KnockCipherType int

type KnockCipher struct {
	cipher.AEAD
	cipherKey []byte
	nonceSalt []byte
}

func New(knockCipher KnockCipherType, key, nonceSalt []byte) (kc *KnockCipher, err error) {
	switch knockCipher {
	case AesGcm:
		return newAesGcmCipher(key, nonceSalt)
	default:
		return newChacha20Poly1305Cipher(key, nonceSalt)
	}
}

func (kc *KnockCipher) Encrypt(port, nonceCounter uint16) ([]byte, error) {
	nonce := kc.deriveNonce(nonceCounter)
	portb := uint16toba(port)
	nonceBa := uint16toba(nonceCounter)
	return append(nonceBa, kc.Seal(nil, nonce, portb, nil)...), nil
}

func (kc *KnockCipher) deriveNonce(nonceCounter uint16) []byte {
	nc := uint16toba(nonceCounter)
	return pbkdf2.Key(nc, kc.nonceSalt, 10000, kc.NonceSize(), sha3.New512)
}

func GenerateRandomData(size uint32) ([]byte, error) {
	b := make([]byte, size)
	n, err := rand.Read(b)
	if err != nil {
		return b, err
	}
	if n != len(b) {
		return b, fmt.Errorf("generated %d bytes, requested %d", n, size)
	}
	return b, err
}

func uint16toba(u uint16) []byte {
	return []byte{uint8(u >> 8), uint8(u & 0xff)}
}
