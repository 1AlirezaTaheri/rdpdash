package ntlm

import "encoding/binary"

// MD4 (RFC 1320). crypto/md4 was removed from the Go stdlib, so a
// compact implementation lives here. Tested against known MD4 vectors
// (see ntlm_test.go).

var (
	md4K2 = [...]uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	md4K3 = [...]uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
	md4S  = [64]uint{
		3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
		3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
		3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
		3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
	}
)

func md4Sum(data []byte) [16]byte {
	h := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}

	msg := make([]byte, len(data))
	copy(msg, data)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var lb [8]byte
	binary.LittleEndian.PutUint64(lb[:], uint64(len(data))*8)
	msg = append(msg, lb[:]...)

	rotl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

	for off := 0; off < len(msg); off += 64 {
		var m [16]uint32
		for i := 0; i < 16; i++ {
			m[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		a, b, c, d := h[0], h[1], h[2], h[3]

		for i := 0; i < 48; i++ {
			var f, k, constx uint32
			switch {
			case i < 16:
				f = (b & c) | (^b & d)
				k = m[i]
				constx = 0
			case i < 32:
				f = (b & c) | (b & d) | (c & d)
				k = m[md4K2[i-16]]
				constx = 0x5A827999
			default:
				f = b ^ c ^ d
				k = m[md4K3[i-32]]
				constx = 0x6ED9EBA1
			}
			a = rotl(a+f+k+constx, md4S[i])
			a, b, c, d = d, a, b, c
		}

		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
	}

	var out [16]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}
