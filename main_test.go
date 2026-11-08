package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"rdpdash/internal/rdp"
)

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func buildBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		name := "rdpdash_test_bin"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		dir, err := os.MkdirTemp("", "rdpdash-test-bin")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, name)
		// -s strips the symbol table. Without it Windows Defender flags
		// the freshly built binary as unwanted software (see the README
		// section on false positives) and every CLI test fails to start.
		cmd := exec.Command("go", "build", "-ldflags=-s", "-o", binPath, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("failed to build test binary: %v, output:\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		os.RemoveAll(filepath.Dir(binPath))
	}
	os.Exit(code)
}

func TestCLISuccessAndFail(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("alice", "P@ssw0rd123!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	// 1. Valid credential probe: a run with a hit exits with exitHit (3)
	// so that scripts can branch on it without scraping the summary.
	code, outStr := runCode(t, exec.Command(bin, "-U", "alice", "-P", "P@ssw0rd123!", addr))
	if code != exitHit {
		t.Fatalf("valid probe: exit %d, want %d, output:\n%s", code, exitHit, outStr)
	}
	if !strings.Contains(outStr, "[+]") || !strings.Contains(outStr, "SUCCESS") {
		t.Errorf("expected success output with '[+]' and 'SUCCESS', got:\n%s", outStr)
	}

	// 2. Invalid credential probe: nothing found, clean exit 0.
	code, outStr = runCode(t, exec.Command(bin, "-U", "alice", "-P", "WrongPassword", addr))
	if code != exitOK {
		t.Fatalf("invalid probe: exit %d, want %d, output:\n%s", code, exitOK, outStr)
	}
	if !strings.Contains(outStr, "[-]") || !strings.Contains(outStr, "FAIL") {
		t.Errorf("expected fail output with '[-]' and 'FAIL', got:\n%s", outStr)
	}
}

func TestCLIFilesAndCSV(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("bob", "SecretKey99")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	tmpDir := t.TempDir()
	targetsFile := filepath.Join(tmpDir, "targets.txt")
	credsFile := filepath.Join(tmpDir, "creds.txt")
	csvOutFile := filepath.Join(tmpDir, "results.csv")

	if err := os.WriteFile(targetsFile, []byte(addr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credsContent := "bob:SecretKey99\nbob:WrongOne\n"
	if err := os.WriteFile(credsFile, []byte(credsContent), 0o600); err != nil {
		t.Fatal(err)
	}

	code, outStr := runCode(t, exec.Command(bin, "-f", targetsFile, "-c", credsFile, "-o", csvOutFile))
	if code != exitHit {
		t.Fatalf("CLI run: exit %d, want %d (one hit), output:\n%s", code, exitHit, outStr)
	}

	csvData, err := os.ReadFile(csvOutFile)
	if err != nil {
		t.Fatalf("failed to read output csv: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(csvData))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("invalid csv output: %v", err)
	}

	// Header + 2 entries
	if len(records) != 3 {
		t.Fatalf("expected 3 csv rows (header + 2 results), got %d rows", len(records))
	}
	if records[0][0] != "host" || records[0][3] != "password" || records[0][4] != "status" {
		t.Errorf("unexpected csv header: %v", records[0])
	}
	// Probes finish concurrently, so the CSV row order is not fixed.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	statusCount := map[string]int{}
	for _, rec := range records[1:] {
		statusCount[rec[4]]++
		if rec[0] != host || rec[1] != port {
			t.Errorf("csv host/port = %s/%s, want %s/%s", rec[0], rec[1], host, port)
		}
		if rec[2] != "bob" {
			t.Errorf("csv user = %q, want bob", rec[2])
		}
		if rec[4] == "SUCCESS" && rec[3] != "SecretKey99" {
			t.Errorf("csv password on SUCCESS = %q, want the real secret", rec[3])
		}
		if rec[4] == "FAIL" && rec[3] != "<masked>" {
			t.Errorf("csv password on FAIL = %q, want <masked>", rec[3])
		}
	}
	if statusCount["SUCCESS"] != 1 || statusCount["FAIL"] != 1 {
		t.Errorf("status counts = %v, want one SUCCESS and one FAIL", statusCount)
	}
}

func TestCLIStdinPiping(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("carol", "Pass!234")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	cmd := exec.Command(bin, "-U", "carol", "-P", "Pass!234")
	cmd.Stdin = strings.NewReader(addr + "\n")
	code, outStr := runCode(t, cmd)
	if code != exitHit {
		t.Fatalf("stdin probe: exit %d, want %d, output:\n%s", code, exitHit, outStr)
	}
	if !strings.Contains(outStr, "[+]") || !strings.Contains(outStr, "SUCCESS") {
		t.Errorf("expected success on stdin input, got:\n%s", outStr)
	}
}

func TestCLIQuietMode(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("dave", "CorrectP@ss")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	// Quiet mode on failure should not output "[-]"
	cmd := exec.Command(bin, "-q", "-U", "dave", "-P", "IncorrectP@ss", addr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("quiet probe command failed: %v, output:\n%s", err, string(out))
	}
	outStr := string(out)
	if strings.Contains(outStr, "[-]") {
		t.Errorf("expected quiet mode to suppress '[-]', got:\n%s", outStr)
	}
}

func TestCLIPositionalArgAnywhere(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("eva", "P@ss1234")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	// Target placed before -U and -P
	code, outStr := runCode(t, exec.Command(bin, addr, "-U", "eva", "-P", "P@ss1234"))
	if code != exitHit {
		t.Fatalf("positional arg at start: exit %d, want %d, output:\n%s", code, exitHit, outStr)
	}
	if !strings.Contains(outStr, "[+]") || !strings.Contains(outStr, "SUCCESS") {
		t.Errorf("expected success with positional target at start, got:\n%s", outStr)
	}
}

// TestCLIManyJobsNoDeadlock runs far more probes than the worker/channel
// buffers can hold, which used to block the dispatcher forever.
func TestCLIManyJobsNoDeadlock(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("frank", "P@ssw0rd!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	tmpDir := t.TempDir()
	targetsFile := filepath.Join(tmpDir, "targets.txt")
	credsFile := filepath.Join(tmpDir, "creds.txt")

	// 30 targets × 4 credentials = 120 jobs with only 2 workers.
	if err := os.WriteFile(targetsFile, []byte(strings.Repeat(addr+"\n", 30)), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := strings.Repeat("frank:P@ssw0rd!\nfrank:nope\nfrank:P@ssw0rd!\nfrank:nope\n", 1)
	if err := os.WriteFile(credsFile, []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-f", targetsFile, "-c", credsFile, "-t", "2", "-q")
	code, outStr := runCode(t, cmd)
	if ctx.Err() != nil {
		t.Fatalf("probe batch deadlocked (timeout), output:\n%s", outStr)
	}
	if code != exitHit {
		t.Fatalf("probe batch: exit %d, want %d (60 hits), output:\n%s", code, exitHit, outStr)
	}
	if got := strings.Count(outStr, "[+]"); got != 60 {
		t.Fatalf("expected 60 successes, got %d, output:\n%s", got, outStr)
	}
}

func TestCLIRejectsInvalidWorkers(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("gina", "Passw0rd!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	cmd := exec.Command(bin, "-t", "0", "-U", "gina", "-P", "Passw0rd!", addr)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for -t 0, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "-t must be between") {
		t.Errorf("expected a -t validation error, got:\n%s", string(out))
	}
}

func TestCLIRejectsInvalidTimeout(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("hank", "Passw0rd!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	cmd := exec.Command(bin, "-timeout", "0", "-U", "hank", "-P", "Passw0rd!", addr)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for -timeout 0, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "-timeout must be at least 1") {
		t.Errorf("expected a -timeout validation error, got:\n%s", string(out))
	}
}

// TestCLIPasswordWithLeadingDash guards reorderArgs against mistaking a
// password (or any flag value) for a flag.
func TestCLIPasswordWithLeadingDash(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("iris", "-Secret!42")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	code, outStr := runCode(t, exec.Command(bin, "-U", "iris", "-P", "-Secret!42", addr))
	if code != exitHit {
		t.Fatalf("probe: exit %d, want %d, output:\n%s", code, exitHit, outStr)
	}
	if !strings.Contains(outStr, "SUCCESS") {
		t.Errorf("password starting with '-' was not parsed correctly:\n%s", outStr)
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		in, host, port string
	}{
		{"192.168.1.10", "192.168.1.10", "3389"},
		{"192.168.1.10:4000", "192.168.1.10", "4000"},
		{"[::1]:3390", "::1", "3390"},
		{"example.local", "example.local", "3389"},
	}
	for _, c := range cases {
		h, p := hostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("hostPort(%q) = %q/%q, want %q/%q", c.in, h, p, c.host, c.port)
		}
	}
}

func TestLoadLinesStripsBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("\ufeffhost1\n# comment\nhost2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := loadLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "host1" || lines[1] != "host2" {
		t.Fatalf("loadLines = %q, want [host1 host2]", lines)
	}
}

func TestReorderArgs(t *testing.T) {
	got := reorderArgs([]string{"target", "-U", "user", "-P", "-secret"})
	want := []string{"-U", "user", "-P", "-secret", "target"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("reorderArgs = %q, want %q", got, want)
	}
}

// exitCodeOf runs the binary and returns its exit code, failing the test if
// it cannot be started at all.
func exitCodeOf(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(buildBinary(t), args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("could not run binary for %v: %v, output:\n%s", args, err, string(out))
	}
	return ee.ExitCode(), string(out)
}

// runCode runs cmd and returns its exit code and combined output, failing
// the test only when the process could not be started at all.
func runCode(t *testing.T, cmd *exec.Cmd) (int, string) {
	t.Helper()
	out, err := cmd.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if err != nil && !ok {
		t.Fatalf("could not run %v: %v, output:\n%s", cmd.Args, err, string(out))
	}
	code := 0
	if ok {
		code = ee.ExitCode()
	}
	return code, string(out)
}

// TestCLIPasswordListCrossProduct covers the headline new invocation:
// one target, one username, a password file with two entries. Two probes,
// one of them a success, and the batch summary says so.
func TestCLIPasswordListCrossProduct(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("alice", "RightPass99!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	pwFile := filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(pwFile, []byte("RightPass99!\nWrongPass1!\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, s := runCode(t, exec.Command(bin, "-p", addr, "-u", "alice", "-pl", pwFile))
	if code != exitHit {
		t.Fatalf("run: exit %d, want %d (one hit), output:\n%s", code, exitHit, s)
	}

	// The authorization banner must print on every run.
	if !strings.Contains(s, "AUTHORIZED TESTING ONLY") {
		t.Errorf("expected the authorization banner, got:\n%s", s)
	}
	if got := strings.Count(s, "[+]"); got != 1 {
		t.Errorf("expected exactly 1 success, got %d, output:\n%s", got, s)
	}
	if got := strings.Count(s, "[-]"); got != 1 {
		t.Errorf("expected exactly 1 failure, got %d, output:\n%s", got, s)
	}
	if !strings.Contains(s, "Done: 1 targets, 1 users, 2 passwords, 2 attempts, 1 hits, ") {
		t.Errorf("expected the batch summary line, got:\n%s", s)
	}
}

// TestCLIListUserListPasswordList runs the full three-file interface. Both
// addresses point at the same fake server, so both probes must succeed.
func TestCLIListUserListPasswordList(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("alice", "RightPass99!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	listFile := filepath.Join(tmp, "ips.txt")
	userFile := filepath.Join(tmp, "users.txt")
	pwFile := filepath.Join(tmp, "pw.txt")
	// Two spellings of the same server: they are different strings, so
	// deduplication must keep both.
	if err := os.WriteFile(listFile, []byte(addr+"\nlocalhost:"+port+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userFile, []byte("# users\n\nalice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pwFile, []byte("RightPass99!\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, s := runCode(t, exec.Command(bin, "-list", listFile, "-ul", userFile, "-pl", pwFile))
	if code != exitHit {
		t.Fatalf("run: exit %d, want %d (two hits), output:\n%s", code, exitHit, s)
	}

	if got := strings.Count(s, "[+]"); got != 2 {
		t.Errorf("expected 2 successes (both to the fake server), got %d, output:\n%s", got, s)
	}
	if !strings.Contains(s, "Done: 2 targets, 1 users, 1 passwords, 2 attempts, 2 hits, ") {
		t.Errorf("expected the batch summary line, got:\n%s", s)
	}
}

// TestCLIUnionOfPAndList checks that -p and -list combine: the address in
// both sources is probed once (deduplicated), the one only -list knows is
// added, so two targets in total.
func TestCLIUnionOfPAndList(t *testing.T) {
	bin := buildBinary(t)

	addr, closeFn, err := rdp.StartFakeNLAServer("alice", "RightPass99!")
	if err != nil {
		t.Fatalf("failed to start fake NLA server: %v", err)
	}
	defer closeFn()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	listFile := filepath.Join(tmp, "ips.txt")
	pwFile := filepath.Join(tmp, "pw.txt")
	if err := os.WriteFile(listFile, []byte(addr+"\nlocalhost:"+port+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pwFile, []byte("RightPass99!\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, s := runCode(t, exec.Command(bin, "-p", addr, "-list", listFile, "-u", "alice", "-pl", pwFile))
	if code != exitHit {
		t.Fatalf("run: exit %d, want %d (hits), output:\n%s", code, exitHit, s)
	}

	// -p and -list union with deduplication: addr + localhost, not three.
	if !strings.Contains(s, "Done: 2 targets, 1 users, 1 passwords, 2 attempts, ") {
		t.Errorf("expected a union of 2 targets, got:\n%s", s)
	}
}

// TestCLIAmbiguousUserFlags: -u and -U both supply usernames; the run must
// refuse with exit code 2 rather than pick one silently.
func TestCLIAmbiguousUserFlags(t *testing.T) {
	code, out := exitCodeOf(t, "-u", "alice", "-U", "bob", "127.0.0.1")
	if code != 2 {
		t.Errorf("exit code = %d, want 2, output:\n%s", code, out)
	}
	if !strings.Contains(out, "ambiguous") {
		t.Errorf("expected an 'ambiguous' error message, got:\n%s", out)
	}
}

// TestCLIAmbiguousPasswordFlags: -pl and -c both supply passwords.
func TestCLIAmbiguousPasswordFlags(t *testing.T) {
	tmp := t.TempDir()
	pwFile := filepath.Join(tmp, "pw.txt")
	credFile := filepath.Join(tmp, "creds.txt")
	if err := os.WriteFile(pwFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credFile, []byte("bob:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out := exitCodeOf(t, "-pl", pwFile, "-c", credFile, "127.0.0.1")
	if code != 2 {
		t.Errorf("exit code = %d, want 2, output:\n%s", code, out)
	}
	if !strings.Contains(out, "ambiguous") {
		t.Errorf("expected an 'ambiguous' error message, got:\n%s", out)
	}
}

// TestCLIMissingTargets: usernames and passwords are fine, nothing names a
// target — exit code 2 with a message that says what is missing. Stdin is
// the null device here, so it must not be mistaken for piped input.
func TestCLIMissingTargets(t *testing.T) {
	bin := buildBinary(t)
	tmp := t.TempDir()
	pwFile := filepath.Join(tmp, "pw.txt")
	if err := os.WriteFile(pwFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-u", "alice", "-pl", pwFile)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a failure when no target is given, got success:\n%s", string(out))
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error: %v", err)
	}
	if ee.ExitCode() != 2 {
		t.Errorf("exit code = %d, want 2, output:\n%s", ee.ExitCode(), string(out))
	}
	if !strings.Contains(string(out), "no targets") {
		t.Errorf("expected a 'no targets' message, got:\n%s", string(out))
	}
}
