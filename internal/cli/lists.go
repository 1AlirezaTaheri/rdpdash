package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ReadLines reads a list file, one entry per line. A UTF-8 BOM on the
// first line is stripped, surrounding whitespace is trimmed, and blank
// lines and lines starting with '#' are skipped. The path "-" reads
// standard input. An empty result is an error that names the file.
func ReadLines(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	var fp *os.File
	display := path
	if path == "-" {
		fp = os.Stdin
		display = "standard input"
	} else {
		var err error
		fp, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer fp.Close()
	}

	var out []string
	sc := bufio.NewScanner(fp)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s contains no entries", display)
	}
	return out, nil
}

// NormalizeArgs rewrites the single-dash spellings into the long options
// they stand for: -list -> --ip-list, -ul -> --user-list, -pl -> --password-list.
func NormalizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		switch {
		case strings.HasPrefix(arg, "-list="):
			out[i] = "--ip-list=" + arg[len("-list="):]
		case strings.HasPrefix(arg, "-ul="):
			out[i] = "--user-list=" + arg[len("-ul="):]
		case strings.HasPrefix(arg, "-pl="):
			out[i] = "--password-list=" + arg[len("-pl="):]
		case arg == "-list":
			out[i] = "--ip-list"
		case arg == "-ul":
			out[i] = "--user-list"
		case arg == "-pl":
			out[i] = "--password-list"
		default:
			out[i] = arg
		}
	}
	return out
}

// Dedupe drops duplicates while preserving order. ignoreCase folds case
// for usernames and targets; passwords keep their case.
func Dedupe(values []string, ignoreCase bool) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		k := v
		if ignoreCase {
			k = strings.ToLower(v)
		}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// Set is a membership set with a chosen case rule.
type Set struct {
	entries    map[string]struct{}
	ignoreCase bool
}

func NewSet(ignoreCase bool, seed ...string) *Set {
	s := &Set{entries: make(map[string]struct{}, len(seed)), ignoreCase: ignoreCase}
	for _, v := range seed {
		s.entries[s.key(v)] = struct{}{}
	}
	return s
}

func (s *Set) Insert(value string) bool {
	k := s.key(value)
	if _, ok := s.entries[k]; ok {
		return false
	}
	s.entries[k] = struct{}{}
	return true
}

func (s *Set) key(value string) string {
	if s.ignoreCase {
		return strings.ToLower(value)
	}
	return value
}
