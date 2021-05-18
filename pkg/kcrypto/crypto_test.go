package kcrypto

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestNew(t *testing.T) {
	if _, err := New(Chacha20Poly1305, []byte("1"), []byte("")); err == nil {
		t.Fatal("expected bad key length, but creation successful")
	}

	if _, err := New(AesGcm, []byte("1"), []byte("")); err == nil {
		t.Fatal("expected bad key length, but creation successful")
	}

	if _, err := New(Chacha20Poly1305, []byte("1234567890123456"), []byte("")); err == nil {
		t.Fatal("expected bad key length, but creation successful")
	}

	key := []byte("12345678901234567890123456789012")
	aead, err := New(Chacha20Poly1305, key, []byte("noncesalt1"))
	if err != nil {
		t.Fatalf("unexpected error on AEAD creation %v", err)
	}
	if aead == nil {
		t.Fatal("expected aead, got nil")
	}

	aead, err = New(AesGcm, key, []byte("noncesalt2"))
	if err != nil {
		t.Fatalf("unexpected error on AEAD creation %v", err)
	}
	if aead == nil {
		t.Fatal("expected aead, got nil")
	}
}

func TestGenerateRandomData(t *testing.T) {
	var size uint32 = 32
	b, err := GenerateRandomData(size)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if uint32(len(b)) != size {
		t.Fatalf("expected size of %d, got %d", size, len(b))
	}
}

func TestUint16toba(t *testing.T) {
	var m map[uint16][]byte = map[uint16][]byte{
		0x1a1b: {0x1a, 0x1b},
		0xaabb: {0xaa, 0xbb},
		0x0001: {0x00, 0x01},
		0x53d6: {0x53, 0xd6},
	}
	for k, v := range m {
		ub := uint16toba(k)
		if !bytes.Equal(v, ub) {
			t.Fatalf("byte arrays are not equal %v != %v", v, ub)
		}
	}
}

func encryptTest(t *testing.T, kc *KnockCipher) {
	portTestCount := 10
	counterTestCount := 3
	ports := make([]uint16, portTestCount)
	counters := make([]uint16, counterTestCount)

	for i := 0; i < portTestCount; i++ {
		ports[i] = uint16(rand.Int())
	}
	for i := 0; i < counterTestCount; i++ {
		counters[i] = uint16(rand.Int())
	}

	for _, port := range ports {
		for _, counter := range counters {
			b, err := kc.Encrypt(port, counter)
			if err != nil {
				t.Fatalf("unexpected encryption error %v", err)
			}

			nonceBaOriginal, ciphertext := b[0:2], b[2:]
			nonce, portb, nonceBa := kc.deriveNonce(counter), uint16toba(port), uint16toba(counter)

			if !bytes.Equal(nonceBaOriginal, nonceBa) {
				t.Fatalf("expected equal nonces %v != %v", nonceBa, nonceBaOriginal)
			}

			plaintext, err := kc.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				t.Fatalf("unexpected decryption error %v", err)
			}
			if !bytes.Equal(plaintext, portb) {
				t.Fatalf("encryption is failing with port %d and counter %d", port, counter)
			}
		}
	}
}

func deriveNonceTest(t *testing.T, kc *KnockCipher) {
	nonce00 := kc.deriveNonce(0)
	nonce01 := kc.deriveNonce(0)
	nonce10 := kc.deriveNonce(1)
	if !bytes.Equal(nonce00, nonce01) {
		t.Fatalf("expected equal nonces but got %v != %v", nonce00, nonce01)
	}
	if bytes.Equal(nonce00, nonce10) {
		t.Fatalf("expected different nonces but got %v != %v", nonce00, nonce10)
	}
	for _, l := range []int{len(nonce00), len(nonce01), len(nonce10)} {
		if kc.NonceSize() != l {
			t.Fatalf("expected nonces of size %d, got %d", kc.NonceSize(), l)
		}
	}
}
