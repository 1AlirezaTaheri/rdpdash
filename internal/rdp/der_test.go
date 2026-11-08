package rdp

// der_test.go — wire-format tests for the CredSSP structures.

import (
	"bytes"
	"testing"
)

func TestTSRequestEncoding(t *testing.T) {
	tok := append([]byte("NTLMSSP\x00"), 0xde, 0xad)
	buf := encodeTSRequest(tsFields{negoToken: tok})

	if buf[0] != 0x30 {
		t.Fatalf("TSRequest is not a SEQUENCE: %x", buf[0])
	}
	// version must be [0] { INTEGER 2 }
	if !bytes.Contains(buf, []byte{0xA0, 0x03, 0x02, 0x01, credsspVersion}) {
		t.Errorf("missing [0] INTEGER version: %x", buf)
	}
	// negoTokens must be [1], not [0]
	if !bytes.Contains(buf, []byte{0xA1}) {
		t.Errorf("negoTokens not tagged [1]: %x", buf)
	}

	m, err := parseTSRequest(buf)
	if err != nil {
		t.Fatalf("parseTSRequest: %v", err)
	}
	if m.version != credsspVersion {
		t.Errorf("version = %d, want %d", m.version, credsspVersion)
	}
	if !bytes.Equal(m.negoToken, tok) {
		t.Errorf("negoToken = %x, want %x", m.negoToken, tok)
	}
}

func TestTSRequestCombinedAndErrorCode(t *testing.T) {
	// A final client message carries negoTokens and pubKeyAuth together;
	// a server rejection carries only errorCode.
	buf := encodeTSRequest(tsFields{negoToken: []byte("tok"), pubKeyAuth: []byte("sealed-key")})
	m, err := parseTSRequest(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(m.negoToken) != "tok" || string(m.pubKeyAuth) != "sealed-key" {
		t.Fatalf("fields lost: nego=%q pub=%q", m.negoToken, m.pubKeyAuth)
	}

	errBuf := tlv(0x30, append(
		tlv(tagVersion, tlv(0x02, []byte{2})),
		tlv(tagErrorCode, []byte{0xC0, 0x00, 0x00, 0x6D})...,
	))
	em, err := parseTSRequest(errBuf)
	if err != nil {
		t.Fatal(err)
	}
	if !em.hasError || em.errorCode != 0xC000006D {
		t.Fatalf("errorCode = %08x (present=%v), want c000006d", em.errorCode, em.hasError)
	}
	if got := ntStatusError(em.errorCode).Error(); got == "" || !bytes.Contains([]byte(got), []byte("logon failure")) {
		t.Errorf("ntStatusError = %q", got)
	}
}

func TestTsCredentialsEncoding(t *testing.T) {
	der := buildTsCredentials("alice", "S3cr3t!", "CORP")

	// credentials [1] must be A1 { OCTET STRING <DER of TSPasswordCreds> }.
	outer, _, err := nextTLV(der, 0)
	if err != nil || outer.tag != 0x30 {
		t.Fatalf("TSCredentials is not a SEQUENCE: %x (err=%v)", der, err)
	}
	var credsField derElem
	found := false
	for off := 0; off < len(outer.val); {
		e, next, err := nextTLV(outer.val, off)
		if err != nil {
			t.Fatal(err)
		}
		if e.tag == 0xA1 {
			credsField, found = e, true
		}
		off = next
	}
	if !found {
		t.Fatalf("credentials [1] missing: %x", der)
	}
	wrapped, _, err := nextTLV(credsField.val, 0)
	if err != nil || wrapped.tag != 0x04 {
		t.Fatalf("credentials [1] is not an OCTET STRING: %x", credsField.val)
	}

	// Round trip also proves the domain/user tag order: a swapped
	// encoding would return user and domain exchanged.
	user, pass, domain, err := parseTsCredentials(der)
	if err != nil {
		t.Fatalf("parseTsCredentials: %v", err)
	}
	if user != "alice" || pass != "S3cr3t!" || domain != "CORP" {
		t.Fatalf("round trip = %q/%q/%q", user, pass, domain)
	}
}

func TestSplitUserDomain(t *testing.T) {
	u, d := splitUserDomain(`CORP\alice`, "DEFAULT")
	if u != "alice" || d != "CORP" {
		t.Errorf("splitUserDomain = %q/%q, want alice/CORP", u, d)
	}
	u, d = splitUserDomain("bob", "DEFAULT")
	if u != "bob" || d != "DEFAULT" {
		t.Errorf("splitUserDomain = %q/%q, want bob/DEFAULT", u, d)
	}
}
