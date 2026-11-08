package rdp

// credssp_test.go — end-to-end flow test against an in-process fake
// NLA-enabled RDP server (X.224 + TLS + CredSSP/NTLMv2).

import (
	"net"
	"testing"
)

func TestNLAFlow(t *testing.T) {
	addr, clean, err := StartFakeNLAServer("svc.scan", "S3cr3t!")
	if err != nil {
		t.Fatalf("failed to start fake server: %v", err)
	}
	defer clean()

	// valid credentials
	st, err := Check(addr, "svc.scan", "S3cr3t!", "", 5)
	if st != StatusSuccess || err != nil {
		t.Fatalf("valid creds rejected: %v err=%v", st, err)
	}

	// invalid credentials
	st, err = Check(addr, "svc.scan", "wrong", "", 5)
	if st != StatusFailed {
		t.Fatalf("invalid creds not rejected: %v err=%v", st, err)
	}

	// DOMAIN\user syntax
	st, err = Check(addr, `CORP\svc.scan`, "S3cr3t!", "", 5)
	if st != StatusSuccess || err != nil {
		t.Fatalf("DOMAIN\\user valid creds rejected: %v err=%v", st, err)
	}
}

// TestRefused verifies that a TCP connection refused is classified as StatusRefused.
func TestRefused(t *testing.T) {
	// Port 1 on localhost is extremely unlikely to be listening.
	st, err := Check("127.0.0.1:1", "user", "pass", "", 2)
	if st != StatusRefused {
		t.Fatalf("expected StatusRefused, got %v err=%v", st, err)
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in, wantHost, wantPort string
	}{
		{"192.168.1.1", "192.168.1.1", "3389"},
		{"192.168.1.1:4000", "192.168.1.1", "4000"},
		{"[::1]", "::1", "3389"},
		{"[::1]:3390", "::1", "3390"},
		{"http://10.0.0.1", "10.0.0.1", "3389"},
	}
	for _, c := range cases {
		addr, err := normalizeAddr(c.in)
		if err != nil {
			t.Errorf("normalizeAddr(%q) error: %v", c.in, err)
			continue
		}
		gotHost, gotPort, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("normalizeAddr(%q) = %q: SplitHostPort error: %v", c.in, addr, err)
			continue
		}
		if gotHost != c.wantHost || gotPort != c.wantPort {
			t.Errorf("normalizeAddr(%q) = host=%q port=%q, want host=%q port=%q",
				c.in, gotHost, gotPort, c.wantHost, c.wantPort)
		}
	}
}
