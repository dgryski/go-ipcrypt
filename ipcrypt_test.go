package ipcrypt

import (
	"encoding/binary"
	"testing"

	"github.com/dgryski/go-skip32"
)

func TestRoundtrip(t *testing.T) {

	tests := []struct {
		in        uint32
		key       [4]uint32
		encrypted [4]byte
	}{
		// test vector from ipcrypt.py
		{0x01020304, [4]uint32{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}, [4]byte{107, 47, 222, 186}},

		// make sure key is correctly big-endian
		{0x01020304, [4]uint32{0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f}, [4]byte{65, 203, 192, 63}},
	}

	for _, tt := range tests {

		ip := tt.in

		for i := 0; i < 100; i++ {
			ip = Encrypt(tt.key, ip)
		}

		if want32 := binary.BigEndian.Uint32(tt.encrypted[:]); ip != want32 {
			t.Errorf("Encrypt(%08x,%08x)**100=%08x, want %08x", tt.key, tt.in, ip, want32)
		}

		for i := 0; i < 100; i++ {
			ip = Decrypt(tt.key, ip)
		}

		if ip != tt.in {
			t.Errorf("Decrypt(%08x,Encrypt(...,%08x))**100=%08x, want %08x", tt.key, tt.in, ip, tt.in)
		}
	}
}

func BenchmarkIPCrypt(b *testing.B) {

	key := [4]uint32{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}
	ip := uint32(0x01020304)
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
