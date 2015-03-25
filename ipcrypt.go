// Package ipcrypt implements IP-format-preserving encryption
/*
https://github.com/veorq/ipcrypt
*/
package ipcrypt

// Encrypt a 4-byte value with a 16-byte key
func Encrypt(key [16]byte, ip [4]byte) [4]byte {
	s := state(ip)
	s = xor4(s, key[:4])
	s = fwd(s)
	s = xor4(s, key[4:8])
	s = fwd(s)
	s = xor4(s, key[8:12])
	s = fwd(s)
	s = xor4(s, key[12:16])
	return s
}

// Decrypt a 4-byte value with a 16-byte key
func Decrypt(key [16]byte, ip [4]byte) [4]byte {
	s := state(ip)
	s = xor4(s, key[12:16])
	s = bwd(s)
	s = xor4(s, key[8:12])
	s = bwd(s)
	s = xor4(s, key[4:8])
	s = bwd(s)
	s = xor4(s, key[:4])
	return s
}

type state [4]byte

func fwd(s state) state {
	b0, b1, b2, b3 := s[0], s[1], s[2], s[3]
	b0 += b1
	b2 += b3
	b0 &= 0xff
	b2 &= 0xff
	b1 = rotl(b1, 2)
	b3 = rotl(b3, 5)
	b1 ^= b0
	b3 ^= b2
	b0 = rotl(b0, 4)
	b0 += b3
	b2 += b1
	b0 &= 0xff
	b2 &= 0xff
	b1 = rotl(b1, 3)
	b3 = rotl(b3, 7)
	b1 ^= b2
	b3 ^= b0
	b2 = rotl(b2, 4)
	return [4]byte{b0, b1, b2, b3}
}

func bwd(s state) state {
	b0, b1, b2, b3 := s[0], s[1], s[2], s[3]
	b2 = rotl(b2, 4)
	b1 ^= b2
	b3 ^= b0
	b1 = rotl(b1, 5)
	b3 = rotl(b3, 1)
	b0 -= b3
	b2 -= b1
	b0 &= 0xff
	b2 &= 0xff
	b0 = rotl(b0, 4)
	b1 ^= b0
	b3 ^= b2
	b1 = rotl(b1, 6)
	b3 = rotl(b3, 3)
	b0 -= b1
	b2 -= b3
	b0 &= 0xff
	b2 &= 0xff
	return [4]byte{b0, b1, b2, b3}
}

func rotl(b byte, r uint) byte {
	return ((b << r) & 0xff) | (b >> (8 - r))
}

func xor4(x [4]byte, y []byte) [4]byte {
	return [4]byte{x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]}
}
