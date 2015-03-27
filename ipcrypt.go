// Package ipcrypt implements IP-format-preserving encryption
/*
https://github.com/veorq/ipcrypt
*/
package ipcrypt

// Encrypt a 4-byte value with a 16-byte key
func Encrypt(key [4]uint32, ip uint32) uint32 {
	s := ip
	s = xor4(s, key[0])
	s = fwd(s)
	s = xor4(s, key[1])
	s = fwd(s)
	s = xor4(s, key[2])
	s = fwd(s)
	s = xor4(s, key[3])
	return s
}

// Decrypt a 4-byte value with a 16-byte key
func Decrypt(key [4]uint32, ip uint32) uint32 {
	s := ip
	s = xor4(s, key[3])
	s = bwd(s)
	s = xor4(s, key[2])
	s = bwd(s)
	s = xor4(s, key[1])
	s = bwd(s)
	s = xor4(s, key[0])
	return s
}

func fwd(s uint32) uint32 {
	b0, b1, b2, b3 := byte(s>>24), byte(s>>16), byte(s>>8), byte(s>>0)
	b0 += b1
	b2 += b3
	b1 = rotl(b1, 2)
	b3 = rotl(b3, 5)
	b1 ^= b0
	b3 ^= b2
	b0 = rotl(b0, 4)
	b0 += b3
	b2 += b1
	b1 = rotl(b1, 3)
	b3 = rotl(b3, 7)
	b1 ^= b2
	b3 ^= b0
	b2 = rotl(b2, 4)
	return uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
}

func bwd(s uint32) uint32 {
	b0, b1, b2, b3 := byte(s>>24), byte(s>>16), byte(s>>8), byte(s>>0)
	b2 = rotl(b2, 4)
	b1 ^= b2
	b3 ^= b0
	b1 = rotl(b1, 5)
	b3 = rotl(b3, 1)
	b0 -= b3
	b2 -= b1
	b0 = rotl(b0, 4)
	b1 ^= b0
	b3 ^= b2
	b1 = rotl(b1, 6)
	b3 = rotl(b3, 3)
	b0 -= b1
	b2 -= b3
	return uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
}

func rotl(b byte, r uint) byte {
	return (b << r) | (b >> (8 - r))
}

func xor4(x, y uint32) uint32 {
	return x ^ y
}
