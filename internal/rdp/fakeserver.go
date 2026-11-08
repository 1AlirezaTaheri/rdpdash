package rdp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rdpdash/internal/ntlm"
)

// StartFakeNLAServer starts an in-process fake NLA server for testing.
// It performs the full CredSSP v2 exchange: NTLMv2 authentication,
// pubKeyAuth binding and sealed credential delegation.
func StartFakeNLAServer(wantUser, wantPass string) (addr string, closeFn func(), err error) {
	return startFakeNLA(wantUser, wantPass, -1)
}

// StartFakeNLAServerLocking is StartFakeNLAServer with an account lockout
// policy: after the wanted user's password has been rejected failAfter
// times, every later logon for that user is answered with
// STATUS_ACCOUNT_LOCKED_OUT — including a correct password, which is how
// a locked Windows account behaves. failAfter <= 0 never locks.
func StartFakeNLAServerLocking(wantUser, wantPass string, failAfter int) (addr string, closeFn func(), err error) {
	return startFakeNLA(wantUser, wantPass, failAfter)
}

func startFakeNLA(wantUser, wantPass string, lockAfter int) (addr string, closeFn func(), err error) {
	cert, err := generateTestCert()
	if err != nil {
		return "", nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	done := make(chan struct{})
	var failures atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = serverHandshakeNLA(conn, cert, wantUser, wantPass, lockAfter, &failures)
			}(c)
		}
	}()

	var once sync.Once
	closeFn = func() {
		once.Do(func() {
			close(done)
			_ = ln.Close()
		})
	}
	return ln.Addr().String(), closeFn, nil
}

func serverHandshakeNLA(conn net.Conn, cert *testCert, wantUser, wantPass string, lockAfter int, failures *atomic.Int32) error {
	// ---- X.224 Connection Confirm: select CredSSP (HYBRID) ------------
	head := make([]byte, 4)
	if err := readAll(conn, head); err != nil {
		return err
	}
	if head[0] != 3 || head[1] != 0 {
		return errDER
	}
	tlen := int(head[2])<<8 | int(head[3])
	if tlen < 4 {
		return errDER
	}
	body := make([]byte, tlen-4)
	if err := readAll(conn, body); err != nil {
		return err
	}
	if len(body) < 2 || body[1] != 0xE0 {
		return errDER
	}

	negRsp := []byte{0x02, 0x00, 0x08, 0x00} // RDP_NEG_RSP type, flags, len
	negRsp = append(negRsp, 0x02, 0, 0, 0)   // HYBRID
	x224 := append([]byte{0x0E, 0xD0, 0, 0, 0, 0, 0}, negRsp...)
	pkt := []byte{0x03, 0x00, byte((4 + len(x224)) >> 8), byte(4 + len(x224))}
	pkt = append(pkt, x224...)
	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	// ---- TLS ------------------------------------------------------------
	tlsSrv := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  cert.PrivateKey,
		}},
	})
	if err := tlsSrv.Handshake(); err != nil {
		return err
	}
	defer tlsSrv.Close()

	// ---- CredSSP ---------------------------------------------------------
	// client T1
	m, err := readTSRequest(tlsSrv)
	if err != nil || m.negoToken == nil {
		return fmt.Errorf("stage t1 err=%v", err)
	}
	t1 := stripSPNEGO(m.negoToken)
	if err := checkType1(t1); err != nil {
		return fmt.Errorf("stage check1: %w", err)
	}

	// server T2 (random challenge)
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return err
	}
	if err := sendChallenge(tlsSrv, challenge[:]); err != nil {
		return err
	}

	// client T3 + pubKeyAuth
	m, err = readTSRequest(tlsSrv)
	if err != nil {
		return fmt.Errorf("stage t3 err=%v", err)
	}
	if m.negoToken == nil || m.pubKeyAuth == nil {
		return errors.New("stage t3: expected negoTokens and pubKeyAuth in one TSRequest")
	}
	auth, err := ntlm.ParseType3(stripSPNEGO(m.negoToken))
	if err != nil {
		return fmt.Errorf("stage parse3: %w", err)
	}
	if !strings.EqualFold(auth.User, wantUser) {
		return fmt.Errorf("stage verify user=%q", auth.User)
	}
	// Lockout policy: once the configured number of rejections has been
	// seen, every later logon is refused with STATUS_ACCOUNT_LOCKED_OUT,
	// correct password or not.
	if lockAfter >= 0 && int(failures.Load()) >= lockAfter {
		_ = writeTSRequest(tlsSrv, tsFields{errorCode: statusAccountLockedOut, hasError: true})
		return fmt.Errorf("stage locked user=%q", auth.User)
	}
	if !ntlm.VerifyType3Response(wantPass, challenge[:], auth) {
		failures.Add(1)
		return fmt.Errorf("stage verify user=%q", auth.User)
	}

	exportedKey, err := ntlm.ExportSessionKey(wantPass, auth)
	if err != nil {
		return fmt.Errorf("stage session key: %w", err)
	}
	clientSealer, err := ntlm.NewSealer(auth.Flags, exportedKey, false)
	if err != nil {
		return fmt.Errorf("stage sealer: %w", err)
	}
	gotKey, err := clientSealer.Unseal(m.pubKeyAuth)
	if err != nil {
		return fmt.Errorf("stage pubkeyauth: %w", err)
	}
	if !equalBytes(gotKey, cert.subjectPublicKey) {
		return errors.New("stage pubkeyauth: server public key mismatch")
	}

	// server pubKeyAuth: public key with its first byte incremented,
	// sealed with the server-to-client key.
	serverSealer, err := ntlm.NewSealer(auth.Flags, exportedKey, true)
	if err != nil {
		return err
	}
	reply := append([]byte{}, cert.subjectPublicKey...)
	reply[0]++
	if err := writeTSRequest(tlsSrv, tsFields{pubKeyAuth: serverSealer.Seal(reply)}); err != nil {
		return err
	}

	// client authInfo (sealed delegated credentials)
	m, err = readTSRequest(tlsSrv)
	if err != nil || m.authInfo == nil {
		return fmt.Errorf("stage authinfo err=%v", err)
	}
	plain, err := clientSealer.Unseal(m.authInfo)
	if err != nil {
		return fmt.Errorf("stage authinfo unseal: %w", err)
	}
	user, pass, _, err := parseTsCredentials(plain)
	if err != nil {
		return fmt.Errorf("stage authinfo parse: %w", err)
	}
	if !strings.EqualFold(user, wantUser) || pass != wantPass {
		return fmt.Errorf("stage authinfo: wrong credentials user=%q", user)
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func checkType1(t1 []byte) error {
	if len(t1) < 32 || string(t1[:8]) != "NTLMSSP\x00" {
		return errDER
	}
	if binary.LittleEndian.Uint32(t1[8:12]) != 1 {
		return errDER
	}
	return nil
}

func sendChallenge(conn net.Conn, challenge []byte) error {
	const srvFlags uint32 = 0x80000000 | // Neg56
		0x40000000 | // NegKeyExchange
		0x20000000 | // Neg128
		0x02000000 | // NegVersion
		0x00800000 | // NegTargetInfo
		0x00080000 | // NegExtendedSec
		0x00008000 | // NegAlwaysSign
		0x00000200 | // NegNTLM
		0x00000020 | // NegSeal
		0x00000010 | // NegSign
		0x00000001 // NegUnicode

	var t2 []byte
	t2 = append(t2, "NTLMSSP\x00"...)
	t2 = binary.LittleEndian.AppendUint32(t2, 2)
	t2 = append(t2, make([]byte, 8)...) // target name fields (empty)
	t2 = binary.LittleEndian.AppendUint32(t2, srvFlags)
	t2 = append(t2, challenge...)
	t2 = append(t2, make([]byte, 8)...) // reserved
	t2 = append(t2, make([]byte, 8)...) // target info (empty)
	t2 = append(t2, make([]byte, 8)...) // version
	_, err := conn.Write(encodeTSRequest(tsFields{negoToken: t2}))
	return err
}

type testCert struct {
	Leaf             *x509.Certificate
	Raw              []byte
	PrivateKey       *rsa.PrivateKey
	subjectPublicKey []byte
}

func generateTestCert() (*testCert, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rdpdash-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	spk, err := subjectPublicKey(leaf)
	if err != nil {
		return nil, err
	}
	return &testCert{Leaf: leaf, Raw: der, PrivateKey: key, subjectPublicKey: spk}, nil
}
