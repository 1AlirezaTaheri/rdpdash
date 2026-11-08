package rdp

import (
	"errors"
)

// der.go — small helpers for the hand-coded ASN.1/DER structures of
// TSRequest (CredSSP) and SPNEGO. Only the shapes those specs use are
// supported.
//
// TSRequest (MS-CSSP §2.2.1), as encoded on the wire:
//
//	SEQUENCE {
//	  [0] { INTEGER version },
//	  [1] { SEQUENCE OF SEQUENCE { [0] { OCTET STRING negoToken } } } OPTIONAL,
//	  [2] { OCTET STRING authInfo }   OPTIONAL,
//	  [3] { OCTET STRING pubKeyAuth } OPTIONAL,
//	  [4] { INTEGER errorCode }       OPTIONAL
//	}

// tlv encodes tag + DER length + content.
func tlv(tag byte, content []byte) []byte {
	l := len(content)
	var lenb []byte
	if l < 0x80 {
		lenb = []byte{byte(l)}
	} else {
		for n := l; n > 0; n >>= 8 {
			lenb = append([]byte{byte(n)}, lenb...)
		}
		lenb = append([]byte{byte(0x80 | len(lenb))}, lenb...)
	}
	out := append([]byte{tag}, lenb...)
	return append(out, content...)
}

var (
	errDER        = errors.New("rdp: malformed DER")
	errNoNegoData = errors.New("rdp: empty CredSSP message")
)

// nextTLV parses the element at off and returns it plus the offset of
// the element that follows it (up to 4 length bytes).
func nextTLV(buf []byte, off int) (e derElem, next int, err error) {
	if off+2 > len(buf) {
		return derElem{}, 0, errDER
	}
	tag := buf[off]
	l := int(buf[off+1])
	off += 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || off+n > len(buf) {
			return derElem{}, 0, errDER
		}
		for l = 0; n > 0; n-- {
			l = l<<8 | int(buf[off])
			off++
		}
	}
	if off+l > len(buf) {
		return derElem{}, 0, errDER
	}
	return derElem{tag: tag, val: buf[off : off+l]}, off + l, nil
}

// derElem is a parsed tag-length-value element.
type derElem struct {
	tag byte
	val []byte
}

// CredSSP context tags (MS-CSSP §2.2.1) and message version.
const (
	credsspVersion = 2 // version-insensitive; Windows accepts 2..6
	tagVersion     = 0xA0
	tagNegoToken   = 0xA0 // NegoData item: negoToken [0] { OCTET STRING }
	tagNego        = 0xA1
	tagAuthInfo    = 0xA2
	tagPubKeyAuth  = 0xA3
	tagErrorCode   = 0xA4
)

// tsFields is the set of optional fields carried by one TSRequest.
type tsFields struct {
	negoToken  []byte
	authInfo   []byte
	pubKeyAuth []byte
	errorCode  uint32
	hasError   bool
}

// encodeTSRequest serializes a client TSRequest.
func encodeTSRequest(f tsFields) []byte {
	body := tlv(tagVersion, tlv(0x02, []byte{credsspVersion}))
	if f.negoToken != nil {
		// NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
		nd := tlv(0x30, tlv(0x30, tlv(tagNegoToken, tlv(0x04, f.negoToken))))
		body = append(body, tlv(tagNego, nd)...)
	}
	if f.authInfo != nil {
		body = append(body, tlv(tagAuthInfo, tlv(0x04, f.authInfo))...)
	}
	if f.pubKeyAuth != nil {
		body = append(body, tlv(tagPubKeyAuth, tlv(0x04, f.pubKeyAuth))...)
	}
	if f.hasError {
		body = append(body, tlv(tagErrorCode, tlv(0x02, derIntBytes(uint64(f.errorCode))))...)
	}
	return tlv(0x30, body)
}

// derIntBytes encodes an INTEGER, keeping DER's rule that the most
// significant bit is the sign bit (an NTSTATUS such as 0xC0000234 needs a
// leading zero octet). parseTSRequest reads the value back unsigned, so
// both the plain and the padded form decode to the same code.
func derIntBytes(v uint64) []byte {
	b := []byte{
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
	for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		b = b[1:]
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return b
}

// tsMessage is a decoded server TSRequest.
type tsMessage struct {
	version    int
	negoToken  []byte
	authInfo   []byte
	pubKeyAuth []byte
	errorCode  uint32
	hasError   bool
}

// parseTSRequest decodes a TSRequest, keeping every field (a message may
// legitimately carry both negoTokens and pubKeyAuth at once).
func parseTSRequest(buf []byte) (tsMessage, error) {
	var m tsMessage
	outer, _, err := nextTLV(buf, 0)
	if err != nil {
		return m, err
	}
	if outer.tag != 0x30 {
		return m, errDER
	}
	off := 0
	for off < len(outer.val) {
		var e derElem
		e, off, err = nextTLV(outer.val, off)
		if err != nil {
			return m, err
		}
		switch e.tag {
		case 0x02: // bare INTEGER version (tolerated)
			m.version = derInt(e.val)
		case tagVersion:
			// [0] version, or a legacy negoTokens wrapper.
			if inner, _, ierr := nextTLV(e.val, 0); ierr == nil && inner.tag == 0x02 {
				m.version = derInt(inner.val)
				continue
			}
			tok, terr := parseSeqToken(e.val)
			if terr != nil {
				return m, terr
			}
			m.negoToken = tok
		case tagNego:
			tok, terr := parseSeqToken(e.val)
			if terr != nil {
				return m, terr
			}
			m.negoToken = tok
		case tagAuthInfo:
			v, uerr := unwrapOctetString(e.val)
			if uerr != nil {
				return m, uerr
			}
			m.authInfo = v
		case tagPubKeyAuth:
			v, uerr := unwrapOctetString(e.val)
			if uerr != nil {
				return m, uerr
			}
			m.pubKeyAuth = v
		case tagErrorCode:
			m.errorCode = uint32(derInt(e.val))
			m.hasError = true
		}
	}
	if m.negoToken == nil && m.authInfo == nil && m.pubKeyAuth == nil && !m.hasError {
		return m, errNoNegoData
	}
	return m, nil
}

// derInt decodes the low 32 bits of a DER INTEGER.
func derInt(b []byte) int {
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return int(v)
}

// parseSeqToken handles NegoData:
//
//	SEQUENCE { SEQUENCE { [0] { OCTET STRING token } } }
//
// and tolerates older variants (bare OCTET STRING or one fewer
// SEQUENCE wrapper).
func parseSeqToken(b []byte) ([]byte, error) {
	if seq, _, err := nextTLV(b, 0); err == nil && seq.tag == 0x30 {
		b = seq.val
	}
	for off := 0; off < len(b); {
		item, next, err := nextTLV(b, off)
		if err != nil {
			return nil, err
		}
		off = next
		switch item.tag {
		case 0x80, 0x81, 0x82, 0x84: // implicit OCTET STRING
			return item.val, nil
		case 0x04: // OCTET STRING
			return item.val, nil
		case 0x30, 0x31, 0xA0: // wrappers
			val, uerr := unwrapOctetString(item.val)
			if uerr == nil {
				return val, nil
			}
			if looksLikeNTLM(item.val) || looksLikeSPNEGO(item.val) {
				return item.val, nil
			}
		default:
			if len(item.val) > 0 {
				return item.val, nil
			}
		}
	}
	return nil, errNoNegoData
}

// unwrapOctetString handles [n] EXPLICIT OCTET STRING / plain contents,
// descending into constructed wrappers (SPNEGO elements) as needed.
func unwrapOctetString(b []byte) ([]byte, error) {
	for off := 0; off < len(b); {
		e, next, err := nextTLV(b, off)
		if err != nil {
			return nil, err
		}
		switch {
		case e.tag == 0x04 || (e.tag >= 0x80 && e.tag <= 0x8A):
			return e.val, nil
		case e.tag&0x20 != 0: // constructed wrapper: descend
			if v, uerr := unwrapOctetString(e.val); uerr == nil {
				return v, nil
			}
		}
		off = next
	}
	return nil, errDER
}

func looksLikeNTLM(b []byte) bool {
	return len(b) > 8 && string(b[:8]) == "NTLMSSP\x00"
}

func looksLikeSPNEGO(b []byte) bool {
	return len(b) > 2 && (b[0] == 0x60 || b[0] == 0xA1)
}
