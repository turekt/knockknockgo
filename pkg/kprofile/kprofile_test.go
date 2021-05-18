package kprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/turekt/knockknockgo/pkg/kcrypto"
)

var (
	profileTestCases []*KnockProfile = []*KnockProfile{{
		Key:          []byte("key1"),
		NonceSalt:    []byte("noncesalt1"),
		NonceCounter: 0,
		Cipher:       kcrypto.Chacha20Poly1305,
		ConnWindow:   50,
		Port:         22,
	}, {
		Key:          []byte("key2"),
		NonceSalt:    []byte("noncesalt2"),
		NonceCounter: 250,
		Cipher:       kcrypto.AesGcm,
		ConnWindow:   0,
		Port:         443,
	}, {
		Key:          []byte("key3"),
		NonceSalt:    []byte("noncesalt3"),
		NonceCounter: 10222,
		Cipher:       kcrypto.Chacha20Poly1305,
		ConnWindow:   10000,
		Port:         80,
	}}
)

func TestSerializeProfile(t *testing.T) {
	for _, p := range profileTestCases {
		p.Serialize(os.TempDir())
	}

	for _, p := range profileTestCases {
		path := filepath.Join(os.TempDir(), strconv.Itoa(int(p.Port))+".json")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("serialization did not create path %s", path)
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			t.Fatalf("failed reading %s", path)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(content, &m); err != nil {
			t.Fatalf("failed marshaling content %s", content)
		}

		if m["nsalt"] != base64.StdEncoding.EncodeToString(p.NonceSalt) {
			t.Fatalf("expected nsalt equal but %s != %s", m["nsalt"], p.NonceSalt)
		}
		if m["key"] != base64.StdEncoding.EncodeToString(p.Key) {
			t.Fatalf("expected key equal but %s != %s", m["key"], p.Key)
		}
		if m["counter"] != float64(p.NonceCounter) {
			t.Fatalf("expected counter equal but %d != %d", m["counter"], p.NonceCounter)
		}
		if m["cipher"] != float64(p.Cipher) {
			t.Fatalf("expected cipher equal but %d != %d", m["cipher"], p.Cipher)
		}
		if m["connwin"] != float64(p.ConnWindow) {
			t.Fatalf("expected connwin equal but %d != %d", m["connwin"], p.ConnWindow)
		}
	}

	for _, p := range profileTestCases {
		os.Remove(filepath.Join(os.TempDir(), strconv.Itoa(int(p.Port))+".json"))
	}
}

func TestDeserializeProfile(t *testing.T) {
	if _, err := Deserialize(0, ""); err == nil {
		t.Fatalf("expected error but deserialization was successful")
	}

	ioutil.WriteFile(filepath.Join(os.TempDir(), "123.json"), []byte("haha"), 0644)
	if _, err := Deserialize(123, os.TempDir()); err == nil {
		t.Fatalf("expected error but deserialization was successful")
	}

	ioutil.WriteFile(filepath.Join(os.TempDir(), "123.json"), []byte("{}"), 0644)
	kp, err := Deserialize(123, os.TempDir())
	if err != nil {
		t.Fatalf("unexpected error on 123 deserialization %v", err)
	}
	if kp.Cipher != kcrypto.Chacha20Poly1305 {
		t.Fatalf("unexpected cipher deserialization to %v", kp.Cipher)
	}
	if kp.ConnWindow != 0 {
		t.Fatalf("unexpected connwindow deserialization to %d", kp.ConnWindow)
	}
	if kp.NonceCounter != 0 {
		t.Fatalf("unexpected counter deserialization to %d", kp.NonceCounter)
	}
	if kp.Port != 123 {
		t.Fatalf("unexpected port deserialization to %d", kp.Port)
	}
	if len(kp.Key) != 0 {
		t.Fatalf("unexpected key deserialization to %s", kp.Key)
	}
	if len(kp.NonceSalt) != 0 {
		t.Fatalf("unexpected nsalt deserialization to %s", kp.NonceSalt)
	}

	os.Remove(filepath.Join(os.TempDir(), "123.json"))
}

func TestDeserializeProfileBulk(t *testing.T) {
	for _, p := range profileTestCases {
		p.Serialize(os.TempDir())
	}

	for _, p := range profileTestCases {
		kp, err := Deserialize(p.Port, os.TempDir())
		if err != nil {
			t.Fatalf("unexpected error on deserialization %v", err)
		}
		compareTest(t, kp, p)
	}

	for _, p := range profileTestCases {
		os.Remove(filepath.Join(os.TempDir(), strconv.Itoa(int(p.Port))+".json"))
	}
}

func TestProfileCreation(t *testing.T) {
	kps := make([]*KnockProfile, 10)
	for i := 0; i < 10; i++ {
		kp, err := NewKnockProfile(uint16(rand.Int()), uint(rand.Int()), kcrypto.KnockCipherType(rand.Int()%2))
		if err != nil {
			t.Fatalf("unexpected error on knock profile creation %v", err)
		}
		if err := kp.Serialize(os.TempDir()); err != nil {
			t.Fatalf("unexpected serialization error %v", err)
		}
		kps[i] = kp
	}

	for _, k := range kps {
		kp, err := Deserialize(k.Port, os.TempDir())
		if err != nil {
			t.Fatalf("unexpected deserialization error %v", err)
		}
		compareTest(t, kp, k)
		os.Remove(filepath.Join(os.TempDir(), strconv.Itoa(int(k.Port))+".json"))
	}
}

func compareTest(t *testing.T, kp, p *KnockProfile) {
	if !bytes.Equal(kp.NonceSalt, p.NonceSalt) {
		t.Fatalf("expected nonce salt equal but %v != %v", kp.NonceSalt, p.NonceSalt)
	}
	if !bytes.Equal(kp.Key, p.Key) {
		t.Fatalf("expected deserialized key equal but %s != %s", kp.Key, p.Key)
	}
	if kp.NonceCounter != p.NonceCounter {
		t.Fatalf("expected nonce counter equal but %d != %d", kp.Cipher, p.NonceCounter)
	}
	if kp.Cipher != p.Cipher {
		t.Fatalf("expected cipher type equal but %d != %d", kp.Cipher, p.Cipher)
	}
	if kp.ConnWindow != p.ConnWindow {
		t.Fatalf("expected connection window equal but %d != %d", kp.ConnWindow, p.ConnWindow)
	}
}
