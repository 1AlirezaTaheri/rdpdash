package ntlm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// Known MD4 vectors (RFC 1320 test suite).
func TestMD4(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
	}
	for _, c := range cases {
		got := md4Sum([]byte(c.in))
		if sp := toHex(got[:]); sp != c.want {
			t.Errorf("md4(%q) = %s, want %s", c.in, sp, c.want)
		}
	}
}

func toHex(b []byte) string {
	const dig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = dig[v>>4]
		out[i*2+1] = dig[v&0xf]
	}
	return string(out)
}

// Known RC4 vector (independently verified with pycryptodome ARC4).
func TestRC4(t *testing.T) {
	out := rc4([]byte{1, 2, 3, 4, 5}, make([]byte, 16))
	if sp := toHex(out); sp != "b2396305f03dc027ccc3524a0a1118a8" {
		t.Errorf("rc4 = %s", sp)
	}
}

// Round trip: client builds T3 for a challenge; server-side verifier
// must confirm the response for the right password, reject others.
func TestNTLMv2Verify(t *testing.T) {
	var chall [8]byte
	rand.Read(chall[:])

	c := NewClient("svc.scan", "S3cr3t!", "CORP")
	post := c.ConsumeType2(makeType2(chall[:]))
	if post != nil {
		t.Fatal(post)
	}
	msg, _, err := c.Type3()
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseType3(msg)
	if err != nil {
		t.Fatal(err)
	}
	if a.User != "svc.scan" || a.Domain != "CORP" {
		t.Fatalf("parse: user=%q domain=%q", a.User, a.Domain)
	}
	if !VerifyType3Response("S3cr3t!", chall[:], a) {
		// debug
		h := ntlmV2Hash("svc.scan", "S3cr3t!", "CORP")
		t.Logf("NT[:16]=%x  recompute=%x", a.NT[:16], hmacMD5(h[:], append(append([]byte{}, chall[:]...), a.NT[16:]...)))
		t.Fatal("verification of own Type3 failed")
	}
	if VerifyType3Response("other", chall[:], a) {
		t.Fatal("verification accepted wrong password")
	}
}

// makeType2 constructs a minimal CHALLENGE message.
func makeType2(challenge []byte) []byte {
	var t2 []byte
	t2 = append(t2, "NTLMSSP\x00"...)
	t2 = binary.LittleEndian.AppendUint32(t2, 2)
	t2 = append(t2, make([]byte, 8)...) // target name fields (empty)
	t2 = binary.LittleEndian.AppendUint32(t2, 0x00080200)
	t2 = append(t2, challenge...)
	t2 = append(t2, make([]byte, 8)...) // reserved
	t2 = append(t2, make([]byte, 8)...) // target info (empty)
	t2 = append(t2, make([]byte, 8)...) // version
	return t2
}

// makeType2WithKEX constructs a CHALLENGE with KeyExchange negotiated.
func makeType2WithKEX(challenge []byte) []byte {
	const flags uint32 = 0x40000000 | // NegKeyExchange
		0x20000000 | // Neg128
		0x02000000 | // NegVersion
		0x00800000 | // NegTargetInfo
		0x00080000 | // NegExtendedSec
		0x00008000 | // NegAlwaysSign
		0x00000200 // NegNTLM
	var t2 []byte
	t2 = append(t2, "NTLMSSP\x00"...)
	t2 = binary.LittleEndian.AppendUint32(t2, 2)
	t2 = append(t2, make([]byte, 8)...) // target name fields (empty)
	t2 = binary.LittleEndian.AppendUint32(t2, flags)
	t2 = append(t2, challenge...)
	t2 = append(t2, make([]byte, 8)...) // reserved
	t2 = append(t2, make([]byte, 8)...) // target info (empty)
	t2 = append(t2, make([]byte, 8)...) // version
	return t2
}

// TestType3Layout validates the AUTHENTICATE message byte layout matches MS-NLMP §2.2.1.3.
func TestType3Layout(t *testing.T) {
	var chall [8]byte
	rand.Read(chall[:])

	// Test with KEX enabled (realistic Windows flags)
	c := NewClient("alice", "P@ssw0rd", "CONTOSO")
	if err := c.ConsumeType2(makeType2WithKEX(chall[:])); err != nil {
		t.Fatal(err)
	}
	msg, _, err := c.Type3()
	if err != nil {
		t.Fatal(err)
	}

	if len(msg) < 72 {
		t.Fatalf("Type3 too short: %d bytes", len(msg))
	}
	if string(msg[0:8]) != "NTLMSSP\x00" {
		t.Errorf("bad signature: %q", msg[0:8])
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 3 {
		t.Errorf("bad message type: %d", binary.LittleEndian.Uint32(msg[8:12]))
	}
	flags := binary.LittleEndian.Uint32(msg[60:64])
	if flags&0x40000000 == 0 {
		t.Errorf("NegKeyExchange flag missing from Type3 at [60:64], flags=0x%08x", flags)
	}
	// Version should be at [64:72]
	if msg[64] != 6 || msg[65] != 1 {
		t.Errorf("version at [64:72] = %d.%d, want 6.1", msg[64], msg[65])
	}

	// EncryptedRandomSessionKey descriptor at [52:60] should be non-zero (KEX active)
	kexLen := binary.LittleEndian.Uint16(msg[52:54])
	if kexLen != 16 {
		t.Errorf("EncryptedRandomSessionKey len at [52:54] = %d, want 16", kexLen)
	}

	// Verify fields can be parsed back correctly.
	a, err := ParseType3(msg)
	if err != nil {
		t.Fatalf("ParseType3 failed: %v", err)
	}
	if a.User != "alice" {
		t.Errorf("parsed user = %q, want %q", a.User, "alice")
	}
	if a.Domain != "CONTOSO" {
		t.Errorf("parsed domain = %q, want %q", a.Domain, "CONTOSO")
	}

	// NTLMv2 blob should start with RespType=1, HiRespType=1 (offset 16 into NT response)
	if len(a.NT) < 20 {
		t.Fatalf("NT response too short: %d bytes", len(a.NT))
	}
	blobHeader := a.NT[16:20] // first 4 bytes of blob: RespType, HiRespType, Reserved1
	if blobHeader[0] != 0x01 || blobHeader[1] != 0x01 {
		t.Errorf("NTLMv2 blob header = %x, want 01 01 00 00", blobHeader)
	}
}

// TestNTLMPasswordHash tests the NTLM hash (MD4 of UTF16LE) against MS-NLMP test vectors.
func TestNTLMPasswordHash(t *testing.T) {
	// MS-NLMP section 4.2.2.2.1
	// Password: "Password"
	// Expected NTLM hash: a4f49c406510bdcab6824ee7c30fd852
	got := ntlmPasswordHash("Password")
	want := "a4f49c406510bdcab6824ee7c30fd852"
	if sp := toHex(got[:]); sp != want {
		t.Errorf("ntlmPasswordHash('Password') = %s, want %s", sp, want)
	}
}

// TestNTLMv2CaseInsensitivity verifies that username casing does not change the NTLMv2 hash.
func TestNTLMv2CaseInsensitivity(t *testing.T) {
	h1 := ntlmV2Hash("administrator", "P@ssw0rd1", "CORP")
	h2 := ntlmV2Hash("ADMINISTRATOR", "P@ssw0rd1", "CORP")
	h3 := ntlmV2Hash("Administrator", "P@ssw0rd1", "CORP")

	if h1 != h2 || h1 != h3 {
		t.Errorf("NTLMv2 hash must be case-insensitive for username: h1=%x, h2=%x, h3=%x", h1, h2, h3)
	}
}

// TestType1NegotiateMessage validates NTLM Type 1 NEGOTIATE_MESSAGE structure.
func TestType1NegotiateMessage(t *testing.T) {
	c := NewClient("user", "pass", "domain")
	t1 := c.Type1()

	if len(t1) < 32 {
		t.Fatalf("Type 1 message too short: %d bytes", len(t1))
	}
	if string(t1[:8]) != "NTLMSSP\x00" {
		t.Errorf("bad Type 1 signature: %q", t1[:8])
	}
	msgType := binary.LittleEndian.Uint32(t1[8:12])
	if msgType != 1 {
		t.Errorf("expected message type 1, got %d", msgType)
	}
	flags := binary.LittleEndian.Uint32(t1[12:16])
	if flags&flagNegNTLM == 0 {
		t.Errorf("expected flagNegNTLM in Type 1 flags: 0x%08x", flags)
	}
	if flags&flagNegKeyExchange == 0 {
		t.Errorf("expected flagNegKeyExchange in Type 1 flags: 0x%08x", flags)
	}
}

// TestType2WithTargetInfo verifies Type 2 parsing preserves targetInfo AV pairs into Type 3 blob.
func TestType2WithTargetInfo(t *testing.T) {
	var chall [8]byte
	rand.Read(chall[:])

	// Construct Type 2 with mock TargetInfo AV-pairs (MsvAvNbDomainName + MsvAvEOL)
	// MsvAvNbDomainName (type=0x0002, len=8, value=UTF16LE("CORP"))
	// MsvAvEOL (type=0x0000, len=0)
	avPair := []byte{0x02, 0x00, 0x08, 0x00}
	avPair = append(avPair, utf16le("CORP")...)
	avPair = append(avPair, 0x00, 0x00, 0x00, 0x00) // EOL

	// Build full Type 2
	t2 := make([]byte, 0, 48+len(avPair))
	t2 = append(t2, "NTLMSSP\x00"...)
	t2 = binary.LittleEndian.AppendUint32(t2, 2)
	t2 = append(t2, make([]byte, 8)...)                   // target name fields
	t2 = binary.LittleEndian.AppendUint32(t2, 0x00880200) // flags: TargetInfo | ExtendedSec | NTLM
	t2 = append(t2, chall[:]...)
	t2 = append(t2, make([]byte, 8)...) // reserved
	// TargetInfo fields: len(2), maxLen(2), offset(4)
	t2 = binary.LittleEndian.AppendUint16(t2, uint16(len(avPair)))
	t2 = binary.LittleEndian.AppendUint16(t2, uint16(len(avPair)))
	t2 = binary.LittleEndian.AppendUint32(t2, 48) // offset to target info
	t2 = append(t2, avPair...)

	c := NewClient("user1", "pass1", "CORP")
	if err := c.ConsumeType2(t2); err != nil {
		t.Fatalf("ConsumeType2 failed: %v", err)
	}
	t3, _, err := c.Type3()
	if err != nil {
		t.Fatalf("Type3 failed: %v", err)
	}

	auth, err := ParseType3(t3)
	if err != nil {
		t.Fatalf("ParseType3 failed: %v", err)
	}

	// Verify that the server verification succeeds with targetInfo included in the blob
	if !VerifyType3Response("pass1", chall[:], auth) {
		t.Errorf("VerifyType3Response failed with targetInfo AV pairs")
	}
}

// TestSealerVectors pins the MS-NLMP RC4 sealing implementation against
// values generated by an independent (Python) implementation of
// impacket's SEAL: same exported key, message-first keystream order,
// HMAC-MD5 checksum over SeqNum||Message.
func TestSealerVectors(t *testing.T) {
	const flags = flagNeg128 | flagNegKeyExchange | flagNegSign | flagNegSeal | flagNegExtendedSec
	exported := make([]byte, 16)
	for i := range exported {
		exported[i] = byte(i)
	}

	s, err := NewSealer(flags, exported, false)
	if err != nil {
		t.Fatal(err)
	}
	got := toHex(s.Seal([]byte("hello world")))
	if got != "01000000ca008906c2764fc9000000001c67f73f1e612a6d64a773" {
		t.Errorf("first sealed message = %s", got)
	}
	msg := make([]byte, 16)
	for i := range msg {
		msg[i] = byte(i)
	}
	got = toHex(s.Seal(msg))
	if got != "01000000cccb16c54d7e22e801000000b205b3862bf0c1fd3686de5c5b8b0792" {
		t.Errorf("second sealed message = %s", got)
	}

	// Server-to-client direction uses the peer magic constants.
	srv, err := NewSealer(flags, exported, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := toHex(srv.Seal([]byte("server-key-bytes"))); got != "01000000eedaa59be71f046400000000220aadfbd4a4348e40a10d9efa03b807" {
		t.Errorf("server-to-client sealed message = %s", got)
	}

	// A fresh peer-side sealer must verify and decrypt the same bytes.
	sender, err := NewSealer(flags, exported, false)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSealer(flags, exported, false)
	if err != nil {
		t.Fatal(err)
	}
	blob := sender.Seal([]byte("hello world"))
	plain, err := receiver.Unseal(blob)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plain) != "hello world" {
		t.Fatalf("Unseal = %q", plain)
	}
	// Tampering must be detected.
	tampered := append([]byte{}, blob...)
	tampered[len(tampered)-1] ^= 0xff
	fresh, err := NewSealer(flags, exported, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Unseal(tampered); err == nil {
		t.Fatal("Unseal accepted a tampered message")
	}
}
