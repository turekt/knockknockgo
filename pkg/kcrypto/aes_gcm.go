package kcrypto

import (
	"crypto/aes"
	"crypto/cipher"
)

func newAesGcmCipher(key, nonceSalt []byte) (*KnockCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCMWithTagSize(block, 12)
	if err != nil {
		return nil, err
	}

	return &KnockCipher{aead, key, nonceSalt}, nil
}
