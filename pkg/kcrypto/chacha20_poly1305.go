package kcrypto

import (
	"golang.org/x/crypto/chacha20poly1305"
)

func newChacha20Poly1305Cipher(key, nonceSalt []byte) (*KnockCipher, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &KnockCipher{aead, key, nonceSalt}, nil
}
