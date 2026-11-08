package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf16"
)

// Package ntlm implements the subset of the NT LAN Manager Security
// Support Provider (MS-NLMP) protocol required to authenticate to an
// RDP server that has Network Level Authentication (CredSSP) enabled.

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// utf16le encodes s as little-endian UTF-16, the wire encoding for all
// textual NTLM structures.
func utf16le(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// ntlmPasswordHash computes NTLM(UTF16LE(password)) = MD4(UTF16LE(password)).
func ntlmPasswordHash(password string) [16]byte {
	return md4Sum(utf16le(password))
}

// ntlmV2Hash = HMAC-MD5(ntlmHash, UPPER(user) + domain).
func ntlmV2Hash(user, password, domain string) [16]byte {
	nth := ntlmPasswordHash(password)
	h := hmacMD5(nth[:], utf16le(upper(user)+domain))
	var out [16]byte
	copy(out[:], h)
	return out
}

// upper upper-cases ASCII bytes (usernames are case-insensitive but
// case-preserving in the hash, matching per-byte Windows behaviour).
func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// negotiate flags (subset, MS-NLMP §2.2.2.5)
const (
	flagNegUnicode     uint32 = 0x00000001
	flagNegSign        uint32 = 0x00000010
	flagNegSeal        uint32 = 0x00000020
	flagNegNTLM        uint32 = 0x00000200
	flagNegAlwaysSign  uint32 = 0x00008000
	flagNegExtendedSec uint32 = 0x00080000
	flagNegTargetInfo  uint32 = 0x00800000
	flagNegVersion     uint32 = 0x02000000
	flagNeg128         uint32 = 0x20000000
	flagNegKeyExchange uint32 = 0x40000000
	flagNeg56          uint32 = 0x80000000
)

type Client struct {
	User, Pass, Domain string

	flags      uint32
	challenge  [8]byte
	targetInfo []byte
	ntlmV2     [16]byte
	randomKey  [16]byte
}

func NewClient(user, pass, domain string) *Client {
	c := &Client{User: user, Pass: pass, Domain: domain}
	// Unicode is mandatory because every string this package emits is
	// UTF-16LE; sign/seal + key exchange are mandatory for CredSSP,
	// which encrypts authInfo/pubKeyAuth with the negotiated key.
	c.flags = flagNegUnicode | flagNegSign | flagNegSeal |
		flagNegNTLM | flagNegAlwaysSign | flagNegExtendedSec |
		flagNeg128 | flagNegKeyExchange | flagNegVersion |
		flagNegTargetInfo | flagNeg56
	rand.Read(c.randomKey[:])
	c.ntlmV2 = ntlmV2Hash(user, pass, domain)
	return c
}

// Flags returns the negotiate flags locked in after ConsumeType2.
func (cm *Client) Flags() uint32 { return cm.flags }

// UTF16LE is the canonical little-endian UTF-16 encoder used across
// NTLM and CredSSP structures.
func UTF16LE(s string) []byte { return utf16le(s) }

// Type1 builds the NEGOTIATE message.
func (cm *Client) Type1() []byte {
	msg := make([]byte, 0, 40)
	msg = append(msg, "NTLMSSP\x00"...)
	msg = binary.LittleEndian.AppendUint32(msg, 1)
	msg = binary.LittleEndian.AppendUint32(msg, cm.flags)
	// domain and workstation supplied zero-length in NEGOTIATE
	msg = binary.LittleEndian.AppendUint16(msg, 0)
	msg = binary.LittleEndian.AppendUint16(msg, 0)
	msg = binary.LittleEndian.AppendUint32(msg, 0)
	msg = binary.LittleEndian.AppendUint16(msg, 0)
	msg = binary.LittleEndian.AppendUint16(msg, 0)
	msg = binary.LittleEndian.AppendUint32(msg, 0)
	// version 6.1.7601
	msg = append(msg, 6, 1, 0, 0, 0, 0, 0, 0)
	return msg
}

var (
	// errBadType2 signals failure to parse the CHALLENGE message
	errBadType2 = errors.New("ntlm: invalid NTLMSSP Type 2 CHALLENGE message")
	// error helper for sessions
)

// ConsumeType2 parses the server's CHALLENGE message and locks in the
// negotiated flags.
func (cm *Client) ConsumeType2(t2 []byte) error {
	if len(t2) < 32 || string(t2[:8]) != "NTLMSSP\x00" {
		return errBadType2
	}
	if binary.LittleEndian.Uint32(t2[8:12]) != 2 {
		return errBadType2
	}
	copy(cm.challenge[:], t2[24:32])

	if len(t2) >= 48 {
		l := int(binary.LittleEndian.Uint16(t2[40:42]))
		o := int(binary.LittleEndian.Uint32(t2[44:48]))
		if o >= 0 && l >= 0 && o+l <= len(t2) {
			cm.targetInfo = t2[o : o+l]
		}
	}

	// intersect flags with the server's advertised set
	if len(t2) >= 24 {
		sflags := binary.LittleEndian.Uint32(t2[20:24])
		keep := flagNegUnicode | flagNegSign | flagNegSeal |
			flagNegNTLM | flagNegAlwaysSign | flagNegExtendedSec |
			flagNeg128 | flagNeg56 | flagNegKeyExchange | flagNegVersion
		cm.flags = (cm.flags & sflags & keep) | (cm.flags & flagNegTargetInfo)
	}
	return nil
}

// Type3 constructs the NTLMv2 AUTHENTICATE message. It returns the
// serialized message and the exported session key used for message
// signing/sealing (MS-NLMP §3.4.5).
// Wire layout (MS-NLMP §2.2.1.3):
//
//	0     signature(8)  8:type(4)  12 lm(8)  20 nt(8)  28 domain(8)
//	36    user(8)       44 ws(8)   52 flags(4)         56 version(8)
//	64    [enc random session key(8) when flagNegKeyExchange]
func (cm *Client) Type3() ([]byte, []byte, error) {
	domain := utf16le(cm.Domain)
	user := utf16le(cm.User)
	ws := utf16le("WORKSTATION")

	var cliRandom [8]byte
	if _, err := rand.Read(cliRandom[:]); err != nil {
		return nil, nil, err
	}

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], filetime())

	// NTLMv2_CLIENT_CHALLENGE (blob) — MS-NLMP §2.2.2.8.2:
	// RespType(1) HiRespType(1) Reserved1(2) Reserved2(4) Timestamp(8)
	// ChallengeFromClient(8) Reserved3(4) AvPairs(variable)
	blob := make([]byte, 0, 28+len(cm.targetInfo)+4)
	blob = append(blob, 0x01, 0x01, 0x00, 0x00) // RespType=1, HiRespType=1, Reserved1
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved2
	blob = append(blob, ts[:]...)               // Timestamp (8 bytes)
	blob = append(blob, cliRandom[:]...)        // ChallengeFromClient (8 bytes)
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved3
	blob = append(blob, cm.targetInfo...)       // AvPairs
	blob = append(blob, 0, 0, 0, 0)             // MsvAvEOL terminator

	// NTLMv2 response:  HMAC-MD5(ntlmv2hash, challenge+blob) + blob
	sig := hmacMD5(cm.ntlmV2[:], append(append([]byte{}, cm.challenge[:]...), blob...))
	ntResp := append(append([]byte{}, sig...), blob...)

	// LMv2 response: HMAC-MD5(ntlmv2hash, challenge+cliRandom) + cliRandom
	lmSig := hmacMD5(cm.ntlmV2[:], append(append([]byte{}, cm.challenge[:]...), cliRandom[:]...))
	lmResp := append(append([]byte{}, lmSig...), cliRandom[:]...)

	// session base key
	sbk := hmacMD5(cm.ntlmV2[:], ntResp[:16])

	useKex := cm.flags&flagNegKeyExchange != 0

	// MS-NLMP §2.2.1.3 AUTHENTICATE_MESSAGE fixed header layout:
	//   [0:8]   Signature
	//   [8:12]  MessageType = 3
	//   [12:52] 5 × field descriptors (LM, NT, Domain, User, Workstation)
	//   [52:60] EncryptedRandomSessionKeyFields
	//   [60:64] NegotiateFlags
	//   [64:72] Version
	// Payload starts at offset 72.
	payloadCap := len(lmResp) + len(ntResp) + len(domain) + len(user) + len(ws)
	if useKex {
		payloadCap += 16
	}
	out := make([]byte, 0, 72+payloadCap)
	out = append(out, "NTLMSSP\x00"...)            // [0:8]
	out = binary.LittleEndian.AppendUint32(out, 3) // [8:12] MessageType

	// [12:52] Five field descriptors (LM, NT, Domain, User, Workstation)
	for i := 0; i < 5; i++ {
		out = binary.LittleEndian.AppendUint16(out, 0) // len
		out = binary.LittleEndian.AppendUint16(out, 0) // maxLen
		out = binary.LittleEndian.AppendUint32(out, 0) // offset
	}

	// [52:60] EncryptedRandomSessionKeyFields — placeholder, filled below
	kexDescOff := len(out) // = 52
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint32(out, 0)

	// [60:64] NegotiateFlags
	out = binary.LittleEndian.AppendUint32(out, cm.flags)

	// [64:72] Version (6.1.7601)
	out = append(out, 6, 1, 0, 0, 0, 0, 0, 0)

	// Payload starts at offset 72
	base := uint64(len(out)) // = 72
	var off uint64 = base

	// Fill in the five field descriptors and append their payloads
	fieldData := [][]byte{lmResp, ntResp, domain, user, ws}
	descOffsets := []int{12, 20, 28, 36, 44}
	for i, f := range fieldData {
		p := descOffsets[i]
		binary.LittleEndian.PutUint16(out[p:], uint16(len(f)))
		binary.LittleEndian.PutUint16(out[p+2:], uint16(len(f)))
		binary.LittleEndian.PutUint32(out[p+4:], uint32(off))
		out = append(out, f...)
		off += uint64(len(f))
	}

	// EncryptedRandomSessionKey (appended if KEX negotiated)
	exported := sbk
	if useKex {
		encKey := rc4(sbk, cm.randomKey[:])
		binary.LittleEndian.PutUint16(out[kexDescOff:], 16)
		binary.LittleEndian.PutUint16(out[kexDescOff+2:], 16)
		binary.LittleEndian.PutUint32(out[kexDescOff+4:], uint32(off))
		out = append(out, encKey...)
		exported = cm.randomKey[:]
	}

	return out, append([]byte{}, exported...), nil
}

// filetimes: 100-nanosecond intervals since 1601-01-01 (MS-DTYP).
func filetime() uint64 {
	return uint64(time.Now().Unix()+11644473600) * 10_000_000
}

// Auth carries the fields decoded from an AUTHENTICATE (Type 3)
// message; used by servers and by protocol tests.
type Auth struct {
	User, Domain string
	LM, NT       []byte
	SessionKey   []byte // EncryptedRandomSessionKey (empty without KEX)
	Flags        uint32
}

// ParseType3 decodes an NTLM Type 3 AUTHENTICATE message.
func ParseType3(msg []byte) (*Auth, error) {
	if len(msg) < 64 || string(msg[:8]) != "NTLMSSP\x00" {
		return nil, errors.New("ntlm: not an NTLMSSP AUTHENTICATE message")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 3 {
		return nil, errors.New("ntlm: not an NTLMSSP Type 3 message")
	}
	get := func(p int) []byte {
		l := int(binary.LittleEndian.Uint16(msg[p : p+2]))
		o := int(binary.LittleEndian.Uint32(msg[p+4 : p+8]))
		if o < 0 || l < 0 || o+l > len(msg) {
			return nil
		}
		return msg[o : o+l]
	}
	a := &Auth{
		LM:         get(12),
		NT:         get(20),
		SessionKey: get(52),
		Flags:      binary.LittleEndian.Uint32(msg[60:64]), // NegotiateFlags at [60:64]
	}
	rawUser := get(36)
	rawDomain := get(28)
	a.User = fromUTF16LE(rawUser)
	a.Domain = fromUTF16LE(rawDomain)
	return a, nil
}

// fromUTF16LE decodes little-endian UTF-16 text (best effort).
func fromUTF16LE(b []byte) string {
	var codes []uint16
	for i := 0; i+1 < len(b); i += 2 {
		codes = append(codes, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(codes))
}

// VerifyType3Response checks (server-side) that the NTLMv2 response in
// a decoded AUTHENTICATE message corresponds to password. The blob
// (client random sequence + AVs) is taken from the NT response itself.
func VerifyType3Response(pass string, challenge []byte, a *Auth) bool {
	if len(a.NT) < 16+8 || len(challenge) != 8 {
		return false
	}
	blob := a.NT[16:]
	nth := ntlmV2Hash(a.User, pass, a.Domain)
	sig := hmacMD5(nth[:], append(append([]byte{}, challenge...), blob...))
	return subtle.ConstantTimeCompare(sig, a.NT[:16]) == 1
}

// ExportSessionKey derives the exported session key from a verified
// AUTHENTICATE message (server side, MS-NLMP §3.4.5).
func ExportSessionKey(pass string, a *Auth) ([]byte, error) {
	if len(a.NT) < 16 {
		return nil, errBadType2
	}
	nth := ntlmV2Hash(a.User, pass, a.Domain)
	sbk := hmacMD5(nth[:], a.NT[:16])
	if a.Flags&flagNegKeyExchange == 0 {
		return sbk, nil
	}
	if len(a.SessionKey) == 0 {
		return nil, errors.New("ntlm: missing encrypted random session key")
	}
	return rc4(sbk, a.SessionKey), nil
}

// FromUTF16LE decodes little-endian UTF-16 text (best effort).
func FromUTF16LE(b []byte) string { return fromUTF16LE(b) }
