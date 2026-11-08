package rdp

// status.go — outcome classification for one credential probe.

import "fmt"

// Status classifies the result of a login attempt against a target.
type Status int

// Result categories, rendered in reports and CSV output.
const (
	StatusSuccess   Status = iota // credentials accepted (NLA handshake completed)
	StatusFailed                  // credentials rejected
	StatusNoNLA                   // server does not require NLA — cannot verify via protocol
	StatusRefused                 // TCP connect refused / no listener
	StatusError                   // other protocol / network error
	StatusLockedOut               // server reported STATUS_ACCOUNT_LOCKED_OUT
)

func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "SUCCESS"
	case StatusFailed:
		return "FAIL"
	case StatusNoNLA:
		return "NO-NLA"
	case StatusRefused:
		return "REFUSED"
	case StatusLockedOut:
		return "LOCKED_OUT"
	default:
		return "ERROR"
	}
}

// IsTerminal reports whether a status is a real answer from the server
// about the credential itself. Anything that is not terminal (an error, a
// refusal, a cancelled probe) says nothing about the password, which is
// why the batch loop treats the two groups differently.
func (s Status) IsTerminal() bool {
	switch s {
	case StatusSuccess, StatusFailed, StatusLockedOut, StatusNoNLA:
		return true
	default:
		return false
	}
}

// Safe, printable status strings.
var _ = fmt.Sprintf
