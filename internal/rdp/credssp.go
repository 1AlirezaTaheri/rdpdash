package rdp

// credssp.go — CredSSP (NLA) client-side flow over a TLS connection
// (MS-CSSP §3.1.5), using the NTLMSSP messages from internal/ntlm.
//
// Client                                               Server
// ------                                               ------
// TSRequest{negoTokens: NTLM T1}                    -->
//                                                   <-- TSRequest{negoTokens: NTLM T2}
// TSRequest{negoTokens: NTLM T3, pubKeyAuth: WrappedServerKey} -->
//                                                   <-- TSRequest{pubKeyAuth: WrappedServerKey+1}
// TSRequest{authInfo: WrappedTSCredentials}         -->
//
// A server pubKeyAuth response means the NTLM exchange succeeded, i.e.
// the username/password pair is valid. Bad credentials make the server
// abort the connection with a TLS alert instead. A server that enforces
// an account lockout policy answers with TSRequest{errorCode} instead,
// which is what StatusLockedOut records.

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"rdpdash/internal/ntlm"
)

// credssp performs the NLA authentication attempt over conn and
// classifies the result. serverKey is the SubjectPublicKey from the
// server's TLS certificate, which must be bound into the exchange.
func credssp(conn net.Conn, serverKey []byte, user, pass, domain string) (Status, error) {
	cm := ntlm.NewClient(user, pass, domain)

	// 1. client → NTLM NEGOTIATE
	if err := writeTSRequest(conn, tsFields{negoToken: cm.Type1()}); err != nil {
		return StatusFailed, err
	}

	// 2. server → NTLM CHALLENGE
	m, err := readTSRequest(conn)
	if err != nil {
		return StatusFailed, err
	}
	if m.hasError {
		return statusForNTStatus(m.errorCode), ntStatusError(m.errorCode)
	}
	if m.negoToken == nil {
		return StatusFailed, errors.New("rdp: missing NTLM challenge")
	}
	if err := cm.ConsumeType2(stripSPNEGO(m.negoToken)); err != nil {
		return StatusFailed, err
	}

	// 3. client → NTLM AUTHENTICATE + sealed server public key
	t3, exportedKey, err := cm.Type3()
	if err != nil {
		return StatusFailed, err
	}
	sealer, err := ntlm.NewSealer(cm.Flags(), exportedKey, false)
	if err != nil {
		return StatusFailed, err
	}
	if err := writeTSRequest(conn, tsFields{
		negoToken:  t3,
		pubKeyAuth: sealer.Seal(serverKey),
	}); err != nil {
		return StatusFailed, err
	}

	// 4. server → sealed public key (proof that NTLM authentication
	// succeeded). A rejected logon closes the connection instead.
	m, err = readTSRequest(conn)
	if err != nil {
		if isLogonRejection(err) {
			return StatusFailed, nil
		}
		return StatusError, err
	}
	if m.hasError {
		return statusForNTStatus(m.errorCode), ntStatusError(m.errorCode)
	}
	if m.pubKeyAuth == nil {
		return StatusFailed, errors.New("rdp: missing pubKeyAuth in CredSSP response")
	}
	if err := verifyServerBinding(cm.Flags(), exportedKey, serverKey, m.pubKeyAuth); err != nil {
		return StatusError, err
	}

	// 5. client → delegated credentials, sealed with the session key.
	// The credential check is already decided at step 4, so a failure to
	// finish this best-effort step does not invalidate the result.
	_ = writeTSRequest(conn, tsFields{
		authInfo: sealer.Seal(buildTsCredentials(user, pass, domain)),
	})
	return StatusSuccess, nil
}

// verifyServerBinding decrypts the server's pubKeyAuth and confirms it
// is the TLS public key with its first byte incremented (MS-CSSP
// §3.1.5 step 4).
func verifyServerBinding(flags uint32, exportedKey, serverKey, wrapped []byte) error {
	srvSealer, err := ntlm.NewSealer(flags, exportedKey, true)
	if err != nil {
		return err
	}
	got, err := srvSealer.Unseal(wrapped)
	if err != nil {
		return fmt.Errorf("rdp: invalid pubKeyAuth signature: %w", err)
	}
	want := append([]byte{}, serverKey...)
	want[0]++
	if !bytes.Equal(got, want) {
		return errors.New("rdp: server public key binding mismatch")
	}
	return nil
}

// statusAccountLockedOut is the NTSTATUS a Windows server sends in
// TSRequest.errorCode once account lockout policy has tripped. It is the
// one rejection that is not about the credential: probing further only
// extends the lockout, so the caller stops instead.
const statusAccountLockedOut uint32 = 0xC0000234

// statusForNTStatus classifies a CredSSP errorCode. Every other rejection
// stays a plain StatusFailed — the operator still gets the NTSTATUS text
// through ntStatusError.
func statusForNTStatus(code uint32) Status {
	if code == statusAccountLockedOut {
		return StatusLockedOut
	}
	return StatusFailed
}

// ntStatusError renders a CredSSP errorCode as a readable error.
func ntStatusError(code uint32) error {
	switch code {
	case 0xC000006D:
		return errors.New("rdp: logon failure (STATUS_LOGON_FAILURE)")
	case 0xC000006A:
		return errors.New("rdp: wrong password (STATUS_WRONG_PASSWORD)")
	case 0xC0000234:
		return errors.New("rdp: account locked out (STATUS_ACCOUNT_LOCKED_OUT)")
	case 0xC0000072:
		return errors.New("rdp: account disabled (STATUS_ACCOUNT_DISABLED)")
	case 0xC000015B:
		return errors.New("rdp: logon type not granted (STATUS_LOGON_TYPE_NOT_GRANTED)")
	default:
		return fmt.Errorf("rdp: CredSSP error 0x%08X", code)
	}
}

// isLogonRejection reports whether err is the server hanging up after a
// failed logon (EOF, connection reset or a TLS access_denied alert).
func isLogonRejection(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return alert == tls.AlertError(49) // access_denied
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "logon failure") ||
		strings.Contains(msg, "connection reset")
}

// writeTSRequest sends one DER TSRequest.
func writeTSRequest(conn net.Conn, f tsFields) error {
	buf := encodeTSRequest(f)
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

// readTSRequest reads one TSRequest DER structure from the stream.
func readTSRequest(conn net.Conn) (tsMessage, error) {
	head := make([]byte, 2)
	if err := readFull(conn, head); err != nil {
		return tsMessage{}, err
	}
	buf := append([]byte{}, head...)
	contentLen := 0
	if h := head[1]; h&0x80 != 0 {
		n := int(h & 0x7f)
		if n == 0 || n > 4 {
			return tsMessage{}, errDER
		}
		ext := make([]byte, n)
		if err := readFull(conn, ext); err != nil {
			return tsMessage{}, err
		}
		buf = append(buf, ext...)
		for _, b := range ext {
			contentLen = contentLen<<8 | int(b)
		}
	} else {
		contentLen = int(head[1])
	}
	if contentLen < 0 || contentLen > 1<<16 {
		return tsMessage{}, errDER
	}
	content := make([]byte, contentLen)
	if err := readFull(conn, content); err != nil {
		return tsMessage{}, err
	}
	buf = append(buf, content...)
	return parseTSRequest(buf)
}

func readFull(conn net.Conn, b []byte) error {
	_, err := io.ReadFull(conn, b)
	return err
}

// stripSPNEGO returns the raw NTLM message from a token that may be
// wrapped in SPNEGO (initial-token 0x60 or negTokenResp 0xA1/0x30).
func stripSPNEGO(tok []byte) []byte {
	if i := bytes.Index(tok, []byte("NTLMSSP\x00")); i >= 0 {
		return tok[i:]
	}
	return tok
}
