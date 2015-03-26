package ipcrypt

import (
	"testing"

	"github.com/dgryski/go-skip32"
)

func TestRoundtrip(t *testing.T) {

	key := [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	ip := [4]byte{1, 2, 3, 4}

	for i := 0; i < 100; i++ {
		ip = Encrypt(key, ip)
	}

	if ip != [4]byte{107, 47, 222, 186} {
		t.Errorf("Encrypt failed")
	}

	for i := 0; i < 100; i++ {
		ip = Decrypt(key, ip)
	}

	if ip != [4]byte{1, 2, 3, 4} {
		t.Errorf("Decrypt failed")
	}
}

func BenchmarkIPCrypt(b *testing.B) {

	key := [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ip := [4]byte{1, 2, 3, 4}

	for i := 0; i < b.N; i++ {
		Encrypt(key, ip)
	}
}

func BenchmarkSkip32(b *testing.B) {

	key := [10]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ip := uint32(0x01020304)

	s, _ := skip32.New(key[:])

	for i := 0; i < b.N; i++ {
		s.Obfus(ip)
	}
}
