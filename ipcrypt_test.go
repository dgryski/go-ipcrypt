package ipcrypt

import "testing"

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
