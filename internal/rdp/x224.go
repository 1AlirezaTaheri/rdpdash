package rdp

// x224.go — TPKT/X.224 connection negotiation (MS-RDPBCGR §1.3.1.1).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Security protocol flags (MS-RDPBCGR §2.2.1.1.1.1).
const (
	protoSTD    uint32 = 0x00000000
	protoTLS    uint32 = 0x00000001
	protoHybrid uint32 = 0x00000002
)

// Negotiation failure codes (MS-RDPBCGR §2.2.1.1.1.1).
const (
	negErrSSLRequired     uint32 = 0x00000001
	negErrSSLNotAllowed   uint32 = 0x00000002
	negErrCertNotOnServer uint32 = 0x00000003
	negErrInconsistentF   uint32 = 0x00000004
	negErrHybridRequired  uint32 = 0x00000005
	negErrSSLWithUserAuth uint32 = 0x00000006
)

var errNotNegotiated = errors.New("rdp: no negotiation structure in response")

func readAll(conn net.Conn, b []byte) error {
	_, err := io.ReadFull(conn, b)
	return err
}

// negotiate performs the X.224 Connection Request/Confirm exchange. It
// returns the security protocol the server selected:
//
//	protoHybrid — server supports NLA (CredSSP); credential checkable
//	protoTLS    — server negotiates TLS but no NLA (logon screen)
//	protoSTD    — plain RDP (very old servers)
//
// Failure codes from the server are surfaced in the returned error.
func negotiate(conn net.Conn, host string, port int) (uint32, error) {
	// RDP_NEG_REQ: type 0x01, flags 0x00, length 8, request TLS|HYBRID
	negReq := []byte{0x01, 0x00, 0x08, 0x00}
	negReq = append(negReq, byte(protoTLS|protoHybrid), 0, 0, 0)

	// X.224 Connection Request (Type 0xE0):
	// li=14, CR code, DST-REF(2)=0, SRC-REF(2)=0, class=0, negReq
	x224 := append([]byte{0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}, negReq...)

	tpktLen := 4 + len(x224)
	pkt := []byte{0x03, 0x00, byte(tpktLen >> 8), byte(tpktLen)}
	pkt = append(pkt, x224...)

	if _, err := conn.Write(pkt); err != nil {
		return 0, err
	}

	head := make([]byte, 4)
	if err := readAll(conn, head); err != nil {
		return 0, err
	}
	if head[0] != 3 {
		return 0, errors.New("rdp: not a TPKT response")
	}
	tlen := int(head[2])<<8 | int(head[3])
	if tlen < 4 || tlen > 4096 {
		return 0, fmt.Errorf("rdp: bad TPKT length %d", tlen)
	}
	body := make([]byte, tlen-4)
	if err := readAll(conn, body); err != nil {
		return 0, err
	}

	// X.224 Confirm PDU: li(1), code=0xD0(1), dst(2), src(2), class(1);
	// optional RDP_NEG structure follows: type, flags, len(2), protocol(4)
	if len(body) < 7 {
		return 0, errors.New("rdp: short X.224 Confirm PDU")
	}
	if body[1] != 0xD0 {
		return 0, fmt.Errorf("rdp: unexpected X.224 response code 0x%02x", body[1])
	}
	if len(body) < 7+8 {
		// No negotiation response: server does not support the protocol
		// extension (legacy behavior): assume standard security.
		return protoSTD, nil
	}
	negType := body[7]
	// RDP_NEG_RSP/FAILURE: type(1) flags(1) len(2) selected protocol(4)
	proto := binary.LittleEndian.Uint32(body[7+4:])
	switch negType {
	case 0x02: // RDP_NEG_RSP
		return proto, nil
	case 0x03: // RDP_NEG_FAILURE
		switch proto {
		case negErrHybridRequired:
			return 0, fmt.Errorf("rdp: server requires CredSSP (HYBRID_REQUIRED)")
		case negErrSSLRequired:
			return 0, fmt.Errorf("rdp: server requires TLS (%s:%d)", host, port)
		case negErrSSLNotAllowed:
			return 0, fmt.Errorf("rdp: server does not allow SSL/TLS")
		case negErrSSLWithUserAuth:
			return 0, fmt.Errorf("rdp: server SSL with user auth required")
		case negErrCertNotOnServer, negErrInconsistentF:
			return 0, fmt.Errorf("rdp: TLS negotiation failure code %v", proto)
		default:
			return 0, fmt.Errorf("rdp: negotiation failure code %v", proto)
		}
	default:
		return 0, errNotNegotiated
	}
}

// setDeadline applies a combined connect + protocol timeout.
func setDeadline(conn net.Conn, timeout int) {
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
}
