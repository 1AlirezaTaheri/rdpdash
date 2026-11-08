package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLinesStripsBOMCommentsAndBlanks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	content := "\ufeff  host1  \n\n# a comment\n\thost2\t\n#host3\nhost4"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadLines(path)
	if err != nil {
		t.Fatalf("ReadLines: %v", err)
	}
	want := []string{"host1", "host2", "host4"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ReadLines = %q, want %q", got, want)
	}
}

func TestReadLinesEmptyFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("# only a comment\n\n   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadLines(path)
	if err == nil || !strings.Contains(err.Error(), "contains no entries") {
		t.Errorf("expected an error, got %v", err)
	}
}

func TestReadLinesEmptyPathReturnsNothing(t *testing.T) {
	got, err := ReadLines("")
	if err != nil || got != nil {
		t.Errorf("ReadLines(\"\") = %q, %v; want nil, nil", got, err)
	}
}

func TestNormalizeArgsRewritesSingleDashSpellings(t *testing.T) {
	in := []string{
		"-list=ips.txt", "-ul=users.txt", "-pl=pw.txt",
		"-list", "ips2.txt", "-ul", "users2.txt", "-pl", "pw2.txt",
		"-p", "1.2.3.4", "-u", "alice", "-f", "f.txt", "-c", "c.txt",
		"-U", "bob", "-P", "secret", "-q", "-v",
	}
	want := []string{
		"--ip-list=ips.txt", "--user-list=users.txt", "--password-list=pw.txt",
		"--ip-list", "ips2.txt", "--user-list", "users2.txt", "--password-list", "pw2.txt",
		"-p", "1.2.3.4", "-u", "alice", "-f", "f.txt", "-c", "c.txt",
		"-U", "bob", "-P", "secret", "-q", "-v",
	}
	got := NormalizeArgs(in)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("NormalizeArgs =\n  %q\nwant\n  %q", got, want)
	}
}

func TestDedupeRules(t *testing.T) {
	users := Dedupe([]string{"Alice", "alice", "BOB", "bob"}, true)
	if strings.Join(users, ",") != "Alice,BOB" {
		t.Errorf("Dedupe(ci) = %q", users)
	}
	pwds := Dedupe([]string{"Secret", "secret", "other"}, false)
	if strings.Join(pwds, ",") != "Secret,secret,other" {
		t.Errorf("Dedupe(exact) = %q", pwds)
	}
}

func TestSetKeepsOrderAndReportsInsertion(t *testing.T) {
	s := NewSet(true, "host1")
	if s.Insert("HOST1") {
		t.Error("HOST1 should be considered already present")
	}
	if !s.Insert("host2") {
		t.Error("host2 should be new")
	}
}
