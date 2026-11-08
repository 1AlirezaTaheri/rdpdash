package ntlm

// RC4 stream cipher (RFC 6229). Used for the NTLM encrypted random
// session key exchange when NEGOTIATE_KEY_EXCH is set.

func rc4(key, data []byte) []byte {
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for pos, v := range data {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		k := s[(int(s[i])+int(s[j]))%256]
		out[pos] = v ^ k
	}
	return out
}
