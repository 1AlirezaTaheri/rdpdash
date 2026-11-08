package rdp

// client.go — top-level login probe: connect, negotiate, TLS, and NLA.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// probeTimeoutSeconds is the default connect/handshake timeout.
const probeTimeoutSeconds = 6

// Check attempts a single credential against an RDP server.
//
//	host may be "ip", "ip:port".
//	user may be "DOMAIN\\user" (which takes precedence over domain).
//
// The whole probe — connect, X.224 negotiation, TLS handshake and the
// CredSSP exchange — is bounded by timeout; it is not a connect timeout
// that the rest of the handshake may then outlive.
//
// The function is safe to run concurrently for distinct targets; servers
// are contacted only when actually probing (no blind data is sent).
func Check(host, user, pass, domain string, timeout int) (Status, error) {
	if timeout <= 0 {
		timeout = probeTimeoutSeconds
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	return CheckContext(ctx, host, user, pass, domain, timeout)
}

// CheckContext is Check with the caller's context. Cancelling ctx aborts
// the probe mid-flight (the connection is closed), which is how the batch
// loop stops wasting attempts on an account that has just been locked out
// somewhere else in the run.
func CheckContext(ctx context.Context, host, user, pass, domain string, timeout int) (Status, error) {
	if timeout <= 0 {
		timeout = probeTimeoutSeconds
	}
	addr, err := normalizeAddr(host)
	if err != nil {
		return StatusError, err
	}
	// An explicit DOMAIN\user wins over the -d default.
	user, domain = splitUserDomain(user, domain)

	// bad renders a transport/handshake failure: a timeout becomes the
	// one message an operator can act on, while a cancelled probe keeps
	// its context.Canceled identity so the caller can tell it apart from
	// a real network error.
	bad := func(err error) (Status, error) {
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return StatusError, err
		}
		if isTimeoutErr(err) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return StatusError, fmt.Errorf("probe timed out after %ds", timeout)
		}
		return StatusError, err
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isRefused(err) && ctx.Err() == nil {
			return StatusRefused, nil
		}
		return bad(err)
	}
	defer conn.Close()

	// One deadline covers every byte of the probe: the TLS wrapper and the
	// CredSSP reads below all share this connection's deadline.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Duration(timeout) * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	// Cancellation closes the connection, which is what turns an in-flight
	// probe into an immediate return instead of a wait for the deadline.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	bareHost, portStr, _ := net.SplitHostPort(addr)
	portNum, _ := strconv.Atoi(portStr)
	if portNum == 0 {
		portNum = 3389
	}

	proto, err := negotiate(conn, bareHost, portNum)
	if err != nil {
		return bad(err)
	}
	switch proto {
	case protoHybrid:
		// NLA available: TLS handshake then CredSSP
	case protoTLS, protoSTD:
		return StatusNoNLA, nil
	default:
		return bad(errors.New("rdp: unsupported negotiated protocol"))
	}

	tcfg := &tls.Config{
		InsecureSkipVerify: true, // RDP hosts typically use self-signed certs
		ServerName:         bareHost,
		// Legacy RDP servers (Windows 2008 R2 and earlier) only offer
		// TLS 1.0; the CredSSP layer is what authenticates the server.
		MinVersion: tls.VersionTLS10,
	}
	tconn := tls.Client(conn, tcfg)
	if err := tconn.Handshake(); err != nil {
		return bad(err)
	}
	defer tconn.Close()

	certs := tconn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return bad(errors.New("rdp: server presented no certificate"))
	}
	pubKey, err := subjectPublicKey(certs[0])
	if err != nil {
		return bad(err)
	}

	st, err := credssp(tconn, pubKey, user, pass, domain)
	if st == StatusError && err != nil {
		return bad(err)
	}
	return st, err
}

// splitUserDomain separates "DOMAIN\user". A domain embedded in the
// username takes precedence over the command-line default.
func splitUserDomain(user, domain string) (string, string) {
	if d, base, ok := strings.Cut(user, "\\"); ok {
		return base, d
	}
	return user, domain
}

// subjectPublicKey returns the DER-encoded SubjectPublicKey bits of a
// certificate (the value Windows expects in CredSSP pubKeyAuth).
func subjectPublicKey(cert *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, err
	}
	if len(spki.PublicKey.Bytes) == 0 {
		return nil, errors.New("rdp: empty subject public key")
	}
	return spki.PublicKey.Bytes, nil
}

func normalizeAddr(host string) (string, error) {
	addr := strings.TrimSpace(host)
	if addr == "" {
		return "", errors.New("rdp: empty host")
	}
	// Strip common URL schemes and any path suffix.
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	// Strip surrounding brackets from bare IPv6 literals (e.g. "[::1]").
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		if p == "" {
			return net.JoinHostPort(h, "3389"), nil
		}
		return addr, nil
	}
	return net.JoinHostPort(addr, "3389"), nil
}

// isTimeoutErr reports whether err is an expired I/O deadline (or a
// context deadline, which is what produces it for a bounded probe).
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timed out")
}

// isRefused reports whether err is a refusal/unreachable condition
// (rather than a timeout or a protocol error).
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "actively refused") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host")
}
