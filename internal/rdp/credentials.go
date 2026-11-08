package rdp

// credentials.go — TSCredentials encoding for the CredSSP authInfo
// payload (MS-CSSP §2.2.1.2).

import (
	"rdpdash/internal/ntlm"
)

// buildTsCredentials encodes the delegated password credentials:
//
//	TSCredentials ::= SEQUENCE {
//	  credType    [0] INTEGER,      -- 1 = TSPasswordCreds
//	  credentials [1] OCTET STRING  -- DER of TSPasswordCreds
//	}
//	TSPasswordCreds ::= SEQUENCE {
//	  domainName [0] OCTET STRING,  -- UTF-16LE, no NUL terminator
//	  userName   [1] OCTET STRING,
//	  password   [2] OCTET STRING
//	}
//
// The [n] wrappers are EXPLICIT: [0] { OCTET STRING ... }.
func buildTsCredentials(user, pass, domain string) []byte {
	domainName := tlv(0xA0, tlv(0x04, ntlm.UTF16LE(domain)))
	userName := tlv(0xA1, tlv(0x04, ntlm.UTF16LE(user)))
	password := tlv(0xA2, tlv(0x04, ntlm.UTF16LE(pass)))
	inner := append(append(domainName, userName...), password...)
	passwordCreds := tlv(0x30, inner)

	creds := tlv(0xA0, tlv(0x02, []byte{1})) // credType
	creds = append(creds, tlv(0xA1, tlv(0x04, passwordCreds))...)
	return tlv(0x30, creds)
}

// parseTsCredentials decodes buildTsCredentials output; used to verify
// the authInfo payload in tests.
func parseTsCredentials(b []byte) (user, pass, domain string, err error) {
	outer, _, err := nextTLV(b, 0)
	if err != nil {
		return "", "", "", err
	}
	if outer.tag != 0x30 {
		return "", "", "", errDER
	}
	var creds []byte
	for off := 0; off < len(outer.val); {
		var e derElem
		e, off, err = nextTLV(outer.val, off)
		if err != nil {
			return "", "", "", err
		}
		if e.tag == 0xA1 {
			creds, err = unwrapOctetString(e.val)
			if err != nil {
				return "", "", "", err
			}
		}
	}
	if creds == nil {
		return "", "", "", errDER
	}

	pc, _, err := nextTLV(creds, 0)
	if err != nil {
		return "", "", "", err
	}
	if pc.tag != 0x30 {
		return "", "", "", errDER
	}
	fields := map[byte]string{}
	for off := 0; off < len(pc.val); {
		var e derElem
		e, off, err = nextTLV(pc.val, off)
		if err != nil {
			return "", "", "", err
		}
		v, uerr := unwrapOctetString(e.val)
		if uerr != nil {
			return "", "", "", uerr
		}
		fields[e.tag] = ntlm.FromUTF16LE(v)
	}
	return fields[0xA1], fields[0xA2], fields[0xA0], nil
}
