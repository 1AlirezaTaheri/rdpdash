package ntlm

// seal.go — MS-NLMP message confidentiality (RC4 + HMAC-MD5). CredSSP
// requires the authInfo and pubKeyAuth fields to be wrapped with the
// session key negotiated by NTLM (MS-CSSP §3.1.5).

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
)

var (
	errNoSealing       = errors.New("ntlm: server did not negotiate NTLM signing/sealing")
	errSealIntegrity   = errors.New("ntlm: message signature check failed")
	errShortSealBlob   = errors.New("ntlm: sealed message too short")
	errBadSealVersion  = errors.New("ntlm: unsupported signature version")
	errShortSessionKey = errors.New("ntlm: exported session key too short")
)

const (
	// Magic constants from MS-NLMP §3.4.5.2 (key generation).
	signMagicClient = "session key to client-to-server signing key magic constant\x00"
	signMagicServer = "session key to server-to-client signing key magic constant\x00"
	sealMagicClient = "session key to client-to-server sealing key magic constant\x00"
	sealMagicServer = "session key to server-to-client sealing key magic constant\x00"
)

// rc4Stream is a stateful RC4 keystream. NTLM sealing chains all
// messages through one stream, so each XOR continues where the
// previous one stopped.
type rc4Stream struct {
	s    [256]byte
	i, j byte
}

func newRC4Stream(key []byte) *rc4Stream {
	r := &rc4Stream{}
	for i := 0; i < 256; i++ {
		r.s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(r.s[i]) + int(key[i%len(key)])) % 256
		r.s[i], r.s[j] = r.s[j], r.s[i]
	}
	return r
}

func (r *rc4Stream) xor(data []byte) []byte {
	out := make([]byte, len(data))
	for k, v := range data {
		r.i++
		r.j += r.s[r.i]
		r.s[r.i], r.s[r.j] = r.s[r.j], r.s[r.i]
		out[k] = v ^ r.s[(int(r.s[r.i])+int(r.s[r.j]))%256]
	}
	return out
}

// Sealer signs and encrypts one direction of an NTLM session.
type Sealer struct {
	signKey []byte
	stream  *rc4Stream
	seq     uint32
	keyExch bool
}

// NewSealer derives the signing and sealing keys from the exported
// session key. server selects the server-to-client key direction; the
// client must use server=false for its own messages.
func NewSealer(flags uint32, exportedSessionKey []byte, server bool) (*Sealer, error) {
	if flags&(flagNegSign|flagNegSeal) != flagNegSign|flagNegSeal {
		return nil, errNoSealing
	}
	if flags&flagNegExtendedSec == 0 {
		return nil, errNoSealing
	}
	if len(exportedSessionKey) < 16 {
		return nil, errShortSessionKey
	}

	signMagic, sealMagic := signMagicClient, sealMagicClient
	if server {
		signMagic, sealMagic = signMagicServer, sealMagicServer
	}

	signKey := md5Sum(append(append([]byte{}, exportedSessionKey...), signMagic...))

	base := exportedSessionKey
	switch {
	case flags&flagNeg128 != 0:
		// full 128-bit key
	case flags&flagNeg56 != 0:
		base = base[:7]
	default:
		base = base[:5]
	}
	sealKey := md5Sum(append(append([]byte{}, base...), sealMagic...))

	return &Sealer{
		signKey: signKey,
		stream:  newRC4Stream(sealKey),
		keyExch: flags&flagNegKeyExchange != 0,
	}, nil
}

func md5Sum(b []byte) []byte {
	sum := md5.Sum(b)
	return sum[:]
}

// Seal returns MESSAGE_SIGNATURE || ciphertext, as expected in the
// CredSSP pubKeyAuth / authInfo fields.
func (s *Sealer) Seal(plain []byte) []byte {
	cipher := s.stream.xor(plain)
	mac := hmacMD5(s.signKey, append(seqBytes(s.seq), plain...))[:8]
	if s.keyExch {
		mac = s.stream.xor(mac)
	}
	sig := make([]byte, 0, 16+len(cipher))
	sig = append(sig, 1, 0, 0, 0)
	sig = append(sig, mac...)
	sig = append(sig, seqBytes(s.seq)...)
	s.seq++
	return append(sig, cipher...)
}

// Unseal verifies and decrypts a sealed message produced by the peer.
func (s *Sealer) Unseal(blob []byte) ([]byte, error) {
	if len(blob) < 16 {
		return nil, errShortSealBlob
	}
	if binary.LittleEndian.Uint32(blob[0:4]) != 1 {
		return nil, errBadSealVersion
	}
	mac := append([]byte{}, blob[4:12]...)
	seq := binary.LittleEndian.Uint32(blob[12:16])
	plain := s.stream.xor(blob[16:])
	if s.keyExch {
		mac = s.stream.xor(mac)
	}
	want := hmacMD5(s.signKey, append(seqBytes(seq), plain...))[:8]
	if !hmac.Equal(mac, want) {
		return nil, errSealIntegrity
	}
	s.seq = seq + 1
	return plain, nil
}

func seqBytes(seq uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, seq)
	return b
}
