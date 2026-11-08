// rdpdash — parallel RDP (NLA) credential checker.
//
// Reads targets and username/password lists, probes RDP servers with
// the CredSSP/NLA authentication flow (NTLMv2 sealed under CredSSP v2)
// and reports which credential pairs are accepted.
//
// Usage examples:
//
//	rdpdash -f targets.txt -c creds.txt -t 64
//	rdpdash -p 192.168.174.133 -u ALIREZA -pl passwords.txt
//	rdpdash -list ips.txt -ul users.txt -pl passwords.txt
//	echo scope.local | rdpdash -c creds.txt
//	rdpdash -f targets.txt -U svc.scan -P 'S3cr3t!' -o out.csv
//	rdpdash --dry-run -list ips.txt -ul users.txt -pl passwords.txt
//
// Only run against systems you are explicitly authorized to test.
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rdpdash/internal/cli"
	"rdpdash/internal/rdp"
)

// buildTag names the build in the banner. It is overridable with
// --build-tag and at link time (`go build -ldflags "-X main.buildTag=X"`),
// so an operator can tell their own builds apart — and so every rebuilt
// binary is a slightly different artefact to antivirus heuristics.
var buildTag = "rdpdash"

// Exit codes. The verdict of a run is a number so scripts can branch on
// it without scraping the summary.
const (
	exitOK          = 0 // finished, nothing found, nobody locked out
	exitFatal       = 1 // internal error (bad output file, ...)
	exitUsage       = 2 // the command line was refused before probing
	exitHit         = 3 // at least one credential was accepted
	exitUnreachable = 4 // every attempt was an error or a refusal
	exitLocked      = 5 // at least one account was locked out during the run
)

// job describes one probe attempt.
type job struct {
	Host, User, Pass string
	// ctx is cancelled when this username is reported locked out, which
	// aborts the probe in flight instead of letting it burn a slot.
	ctx context.Context
}

// result carries the outcome of a probe back to the aggregator.
type result struct {
	j        job
	status   rdp.Status
	err      error
	start    time.Time
	duration time.Duration
}

// hit is one accepted credential, kept for the summary and the hits file.
type hit struct {
	target, user, pass, ts string
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		targets = flag.String("f", "", "targets file, one host[:port] per line (or '-' for stdin)")
		creds   = flag.String("c", "", "credentials file, one 'user:pass' per line")
		user    = flag.String("U", "", "single username (legacy, use -u/-ul)")
		pass    = flag.String("P", "", "single password (legacy, use -pl)")
		domain  = flag.String("d", "", "default domain for bare usernames")
		workers = flag.Int("t", runtime.NumCPU()*2, "number of parallel workers")
		timeout = flag.Int("timeout", 6, "per-probe timeout in seconds")
		outPath = flag.String("o", "", "append results to CSV file")
		quiet   = flag.Bool("q", false, "only print successes")
		debug   = flag.Bool("v", false, "verbose error output")

		// Concurrency control and reporting.
		perHost     = flag.Int("per-host", 5, "max concurrent probes per target host (1..32)")
		dryRun      = flag.Bool("dry-run", false, "print the plan and exit without connecting")
		showFailed  = flag.Bool("show-failed-passwords", false, "write failed attempts' passwords to the CSV")
		noPasswords = flag.Bool("no-passwords", false, "always mask the CSV password column")
		hitsPath    = flag.String("hits-file", "hits.txt", "file for successful credentials ('' disables it)")
		buildTagVal = flag.String("build-tag", buildTag, "build tag shown in the banner")

		// The list-file interface shared with the Rust rdp-audit tool.
		oneTarget = flag.String("p", "", "one target IP/hostname (also --ip)")
		targetLst = flag.String("ip-list", "", "file with target IPs (single-dash: -list)")
		ipAlias   = flag.String("ip", "", "alias for -p")
		oneUser   = flag.String("u", "", "one username (also --username)")
		userLst   = flag.String("user-list", "", "file with usernames (single-dash: -ul)")
		userAlias = flag.String("username", "", "alias for -u")
		passLst   = flag.String("password-list", "", "file with passwords (single-dash: -pl)")
	)

	// The banner carries the build tag and must precede flag.Parse, so
	// that even -h shows it: peek for --build-tag before parsing anything.
	if v, ok := buildTagFromArgs(os.Args[1:]); ok {
		buildTag = v
		*buildTagVal = v
	}
	flag.Usage = printUsage
	printBanner()

	// NormalizeArgs rewrites -list/-ul/-pl to the long options before the
	// parser sees them; Go's flag package has no notion of aliases.
	_ = flag.CommandLine.Parse(reorderArgs(cli.NormalizeArgs(os.Args[1:])))
	buildTag = *buildTagVal

	combo := flag.Args()

	if *workers < 1 || *workers > 1024 {
		fatal("-t must be between 1 and 1024 (got %d)", *workers)
	}
	if *timeout < 1 {
		fatal("-timeout must be at least 1 second (got %d)", *timeout)
	}
	if *perHost < 1 || *perHost > 32 {
		fatal("-per-host must be between 1 and 32 (got %d)", *perHost)
	}

	// A bare invocation still gets the full help, exactly as before; the
	// specific messages below are for runs that asked for something and
	// got it wrong.
	anyInput := *targets != "" || *creds != "" || *oneTarget != "" ||
		*targetLst != "" || *oneUser != "" || *userAlias != "" ||
		*userLst != "" || *passLst != "" || *user != "" || *pass != "" ||
		len(combo) > 0
	if !anyInput {
		usage()
	}

	// Two flags that supply the same list cannot both be honoured. Say so
	// instead of silently picking one: a scan run against the wrong list is
	// worse than a scan that refuses to start.
	newUsers := *oneUser != "" || *userLst != "" || *userAlias != ""
	if newUsers && *user != "" {
		usageError("ambiguous: -u/-ul supply usernames and so does -U; give only one of them")
	}
	if newUsers && *creds != "" {
		usageError("ambiguous: -u/-ul supply usernames and so does -c; give only one of them")
	}
	if *passLst != "" && *creds != "" {
		usageError("ambiguous: -pl supplies passwords and so does -c; give only one of them")
	}
	if *passLst != "" && *pass != "" {
		usageError("ambiguous: -pl supplies passwords and so does -P; give only one of them")
	}

	// Credentials come from two different shapes, and the difference is
	// deliberate: a legacy -c file holds concrete user:pass pairs which are
	// probed exactly as written, while the new model holds a username list
	// and a password list whose cross product is probed. Mixing the two
	// shapes silently would change what an existing -c file does.
	var (
		pairs []string // legacy -c
		users []string // cross model
		pwds  []string // cross model
	)
	if *creds != "" {
		var err error
		pairs, err = loadLines(*creds)
		if err != nil {
			usageError("-c %v", err)
		}
	} else {
		for _, raw := range []string{*oneUser, *userAlias} {
			if v := strings.TrimSpace(raw); v != "" {
				users = append(users, v)
			}
		}
		if *userLst != "" {
			entries, err := cli.ReadLines(*userLst)
			if err != nil {
				usageError("-ul %v", err)
			}
			users = append(users, entries...)
		}
		if len(users) == 0 && *user != "" {
			users = []string{*user}
		}
		if len(users) == 0 {
			usageError("no usernames: give -u, -ul, -U, or -c")
		}
		users = cli.Dedupe(users, true)

		if *passLst != "" {
			entries, err := cli.ReadLines(*passLst)
			if err != nil {
				usageError("-pl %v", err)
			}
			pwds = entries
		}
		if len(pwds) == 0 && *pass != "" {
			pwds = []string{*pass}
		}
		if len(pwds) == 0 {
			usageError("no passwords: give -pl, -P, or -c")
		}
		pwds = cli.Dedupe(pwds, false)
	}

	// Stdin is consulted only when nothing else names a target, exactly as
	// before: a pipe is a source, not a fallback for an empty -f.
	explicit := *targets != "" || *oneTarget != "" || *ipAlias != "" ||
		*targetLst != "" || len(combo) > 0
	autoStdin := false
	if !explicit {
		if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
			*targets = "-"
			autoStdin = true
		}
	}

	var tl []string
	if *targets != "" {
		entries, err := loadLines(*targets)
		if err != nil {
			if autoStdin {
				usageError("%v", err)
			}
			usageError("-f %v", err)
		}
		tl = entries
	}
	// The new flags add to whatever the legacy sources produced. Only new
	// entries pass through the set: duplicates inside a legacy file are
	// part of the old behaviour and are left alone, while a target given
	// twice across sources is probed once.
	seen := cli.NewSet(true, tl...)
	addTarget := func(raw string) {
		v := strings.TrimSpace(raw)
		if v == "" {
			return
		}
		if seen.Insert(v) {
			tl = append(tl, v)
		}
	}
	addTarget(*oneTarget)
	addTarget(*ipAlias)
	if *targetLst != "" {
		entries, err := cli.ReadLines(*targetLst)
		if err != nil {
			usageError("-list %v", err)
		}
		for _, e := range entries {
			addTarget(e)
		}
	}
	// Every positional target counts now; the old code used only the
	// first, and only when -f said nothing.
	for _, pos := range combo {
		addTarget(pos)
	}
	if len(tl) == 0 {
		usageError("no targets: give -p, -list, -f, a positional target, or pipe them on stdin")
	}

	// Count the probes up front so progress reporting does not depend on
	// the dispatch loop, which runs concurrently with result handling.
	jobs := 0
	if pairs != nil {
		for _, cred := range pairs {
			if _, _, ok := splitCred(cred); ok {
				jobs++
			}
		}
		jobs *= len(tl)
	} else {
		jobs = len(tl) * len(users) * len(pwds)
	}
	if jobs == 0 {
		usage()
	}

	// What the batch summary reports as users and passwords: the lists
	// themselves in cross mode, the distinct halves of each pair in legacy
	// pair mode (where the pairs are probed as written, not crossed).
	userCount, passCount := len(users), len(pwds)
	if pairs != nil {
		userCount, passCount = countCredParts(pairs)
	}

	// A dry run stops here: it has everything it needs to describe the
	// batch, and it must not open a single connection.
	if *dryRun {
		printDryRun(tl, users, pwds, pairs, jobs, *workers, *perHost, *timeout)
		return exitOK
	}

	out := newResultSink(*outPath, *quiet, *debug, *showFailed, *noPasswords)
	defer out.Close()

	gate := newHostGate(*perHost)
	locks := newLockRegistry()

	var (
		doneCount atomic.Int64
		hits      atomic.Int64
		fails     atomic.Int64
		refusedN  atomic.Int64
		errorsN   atomic.Int64
		skippedN  atomic.Int64
	)

	jq := make(chan job, *workers*4)
	rq := make(chan result, *workers)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jq {
				if locks.isLocked(j.User) {
					skippedN.Add(1)
					continue
				}
				key := hostKey(j.Host)
				gate.acquire(key)
				// Re-check after the wait: the account may have locked
				// while this job sat in the per-host queue.
				if locks.isLocked(j.User) {
					gate.release(key)
					skippedN.Add(1)
					continue
				}
				ctx := j.ctx
				if ctx == nil {
					ctx = context.Background()
				}
				start := time.Now()
				st, err := rdp.CheckContext(ctx, j.Host, j.User, j.Pass, *domain, *timeout)
				dur := time.Since(start)
				gate.release(key)
				if errors.Is(err, context.Canceled) {
					// Aborted by the lockout: not an attempt, not a
					// network error, nothing to report per attempt.
					skippedN.Add(1)
					continue
				}
				if st == rdp.StatusLockedOut && locks.markLocked(j.User) {
					// Loud, once per account: everything queued for this
					// username is dropped from here on.
					fmt.Printf("[!] ACCOUNT LOCKED OUT for user %s on %s — STOPPING ALL ATTEMPTS for this user\n",
						bareUser(j.User), j.Host)
				}
				rq <- result{j: j, status: st, err: err, start: start, duration: dur}
			}
		}()
	}

	// Dispatch from a separate goroutine; draining rq below keeps the
	// workers moving no matter how many jobs were queued.
	go func() {
		defer close(jq)
		for _, t := range tl {
			target := strings.TrimSpace(t)
			// Legacy -c pairs are probed exactly as written.
			if pairs != nil {
				for _, cred := range pairs {
					u, p, ok := splitCred(cred)
					if !ok {
						continue
					}
					if locks.isLocked(u) {
						skippedN.Add(1)
						continue
					}
					jq <- job{Host: target, User: u, Pass: p, ctx: locks.ctxFor(u)}
				}
				continue
			}
			// The new model is a full cross product: every target against
			// every username against every password.
			for _, u := range users {
				for _, p := range pwds {
					if locks.isLocked(u) {
						skippedN.Add(1)
						continue
					}
					jq <- job{Host: target, User: u, Pass: p, ctx: locks.ctxFor(u)}
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(rq)
	}()

	// Progress on stderr, once a second, with the running totals: on a
	// long batch the operator needs to see that failures are failing for
	// the expected reason, not that the tool has wedged.
	start := time.Now()
	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	progressWG.Add(1)
	go func() {
		defer progressWG.Done()
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				writeProgress(time.Since(start), int64(jobs),
					doneCount.Load(), hits.Load(), fails.Load(), refusedN.Load(), errorsN.Load())
			case <-stopProgress:
				return
			}
		}
	}()

	var got []hit
	for r := range rq {
		doneCount.Add(1)
		out.emit(r)
		switch r.status {
		case rdp.StatusSuccess:
			hits.Add(1)
			host, port := hostPort(r.j.Host)
			got = append(got, hit{
				target: net.JoinHostPort(host, port),
				user:   bareUser(r.j.User),
				pass:   r.j.Pass,
				ts:     r.start.UTC().Format(time.RFC3339),
			})
		case rdp.StatusFailed:
			fails.Add(1)
		case rdp.StatusRefused:
			refusedN.Add(1)
		case rdp.StatusError:
			errorsN.Add(1)
		}
	}

	close(stopProgress)
	progressWG.Wait()
	elapsed := time.Since(start)
	writeProgress(elapsed, int64(jobs), doneCount.Load(), hits.Load(), fails.Load(),
		refusedN.Load(), errorsN.Load())
	fmt.Fprintln(os.Stderr)

	// The batch summary: what went in, what came out, how long it took.
	// "attempts" is what actually ran, so a malformed legacy pair file or
	// a locked-out account can make it smaller than targets × users ×
	// passwords.
	attempts := doneCount.Load()
	fmt.Fprintf(os.Stderr, "Done: %d targets, %d users, %d passwords, %d attempts, %d hits, %ds\n",
		len(tl), userCount, passCount, attempts, hits.Load(),
		int(elapsed.Seconds()))

	printSummary(batchTotals{
		targets: len(tl), users: userCount, passwords: passCount,
		combinations: int64(jobs), attempts: attempts, skipped: skippedN.Load(),
		errors: errorsN.Load(), hits: hits.Load(), fails: fails.Load(),
		locked: locks.lockedCount(), refused: refusedN.Load(),
		elapsed: elapsed, list: got,
	})

	if *hitsPath != "" && len(got) > 0 {
		if err := writeHits(*hitsPath, got); err != nil {
			fmt.Fprintf(os.Stderr, "rdpdash: hits file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Credentials written to %s (%d)\n", *hitsPath, len(got))
		}
	}

	return verdict(hits.Load(), attempts, refusedN.Load(), errorsN.Load(), locks.lockedCount())
}

// verdict maps the tallies of a run onto its exit code.
func verdict(hits, attempts, refused, errs int64, locked int) int {
	switch {
	case hits > 0:
		return exitHit
	case attempts > 0 && refused+errs == attempts:
		return exitUnreachable
	case locked > 0:
		return exitLocked
	default:
		return exitOK
	}
}

// writeProgress repaints the one-line progress meter on stderr.
func writeProgress(elapsed time.Duration, planned, done, hits, fails, refused, errs int64) {
	pct := 0
	if planned > 0 {
		pct = int(done * 100 / planned)
	}
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d probed (%d%%), %d hits, %d fails, %d refused, %d errors   ",
		elapsed.Round(time.Second), done, planned, pct, hits, fails, refused, errs)
}

// batchTotals is everything the closing summary needs.
type batchTotals struct {
	targets, users, passwords       int
	locked                          int
	combinations, attempts, skipped int64
	errors, hits, fails, refused    int64
	elapsed                         time.Duration
	list                            []hit
}

// printSummary renders the multi-line report at the end of a run. The
// one-line "Done:" summary stays for scripts that parse it; this block is
// for the operator reading the terminal.
func printSummary(t batchTotals) {
	fmt.Fprintln(os.Stderr, "\n================ BATCH SUMMARY ================")
	fmt.Fprintf(os.Stderr, "Targets:             %d\n", t.targets)
	fmt.Fprintf(os.Stderr, "Users:               %d\n", t.users)
	fmt.Fprintf(os.Stderr, "Passwords:           %d\n", t.passwords)
	fmt.Fprintf(os.Stderr, "Total combinations:  %d\n", t.combinations)
	fmt.Fprintf(os.Stderr, "Attempts:            %d (%d skipped, %d errors)\n", t.attempts, t.skipped, t.errors)
	fmt.Fprintf(os.Stderr, "Hits (SUCCESS):      %d\n", t.hits)
	fmt.Fprintf(os.Stderr, "Failures (FAIL):     %d\n", t.fails)
	fmt.Fprintf(os.Stderr, "Locked out:          %d\n", t.locked)
	fmt.Fprintf(os.Stderr, "Refused:             %d\n", t.refused)
	fmt.Fprintf(os.Stderr, "Errors:              %d\n", t.errors)
	avg := 0.0
	if t.attempts > 0 {
		avg = t.elapsed.Seconds() / float64(t.attempts)
	}
	fmt.Fprintf(os.Stderr, "Duration:            %ds (%.1fs per attempt avg)\n",
		int(t.elapsed.Seconds()), avg)
	if len(t.list) > 0 {
		fmt.Fprintln(os.Stderr, "\nVALID CREDENTIALS:")
		for _, h := range t.list {
			fmt.Fprintf(os.Stderr, "  %s  %s:%s  (found at %s)\n", h.target, h.user, h.pass, h.ts)
		}
	}
	fmt.Fprintln(os.Stderr, "===============================================")
}

// writeHits saves every accepted credential in the flat
// "host:port  user:pass  timestamp" form, one per line.
func writeHits(path string, list []hit) error {
	var b strings.Builder
	for _, h := range list {
		fmt.Fprintf(&b, "%s  %s:%s  %s\n", h.target, h.user, h.pass, h.ts)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// combo is one planned probe.
type combo struct{ target, user, pass string }

// eachCombination walks the batch in dispatch order. It exists for the
// dry run, which has to show the first and the last combinations without
// storing 343,000 of them.
func eachCombination(tl []string, users, pwds, pairs []string, fn func(int, combo) bool) {
	n := 0
	for _, t := range tl {
		if pairs != nil {
			for _, cred := range pairs {
				u, p, ok := splitCred(cred)
				if !ok {
					continue
				}
				if !fn(n, combo{t, u, p}) {
					return
				}
				n++
			}
			continue
		}
		for _, u := range users {
			for _, p := range pwds {
				if !fn(n, combo{t, u, p}) {
					return
				}
				n++
			}
		}
	}
}

// printDryRun describes the batch — sizes, shape, a time estimate and
// the boundaries of the combination list — and connects to nothing.
func printDryRun(tl []string, users, pwds, pairs []string, jobs, workers, perHost, timeout int) {
	var first, last []string
	eachCombination(tl, users, pwds, pairs, func(i int, c combo) bool {
		line := fmt.Sprintf("%d. %s  user=%s  pass=%s", i+1, c.target, c.user, c.pass)
		if len(first) < 3 {
			first = append(first, line)
		}
		last = append(last, line)
		if len(last) > 3 {
			last = last[1:]
		}
		return true
	})

	// Effective parallelism: workers, but never more than the per-host
	// cap allows across all targets at once.
	par := workers
	if max := perHost * len(tl); par > max {
		par = max
	}
	if par < 1 {
		par = 1
	}
	worst := time.Duration(jobs) / time.Duration(par) * time.Duration(timeout) * time.Second
	typical := time.Duration(float64(jobs) / float64(par) * 0.5 * float64(time.Second))

	fmt.Println("=============================== DRY RUN ===============================")
	fmt.Printf("  Targets:              %d\n", len(tl))
	fmt.Printf("  Users:                %d\n", len(usersOrPairs(users, pairs)))
	fmt.Printf("  Passwords:            %d\n", len(pwdsOrPairs(pwds, pairs)))
	noun := "combinations"
	if jobs == 1 {
		noun = "combination"
	}
	fmt.Printf("  Planned probes:       %d %s\n", jobs, noun)
	fmt.Printf("  Workers (-t):         %d\n", workers)
	fmt.Printf("  Per-host cap:         %d (concurrency per target host)\n", perHost)
	fmt.Printf("  Timeout (-timeout):   %ds\n", timeout)
	fmt.Printf("  Estimated time:       worst case ~%s (every probe spends the full -timeout)\n",
		humanDuration(worst))
	fmt.Printf("                        typical   ~%s (0.5s per probe across %d slots)\n",
		humanDuration(typical), par)
	fmt.Println()
	fmt.Println("  First combinations:")
	for _, l := range first {
		fmt.Printf("    %s\n", l)
	}
	if len(last) > 0 && len(first) > 0 && last[len(last)-1] != first[len(first)-1] {
		fmt.Println("  Last combinations:")
		for _, l := range last {
			fmt.Printf("    %s\n", l)
		}
	}
	fmt.Println("========================================================================")
	fmt.Println("dry run: no connections were opened.")
}

// usersOrPairs / pwdsOrPairs keep the dry-run counts aligned with what a
// legacy -c file really contributes.
func usersOrPairs(users []string, pairs []string) []string {
	if pairs == nil {
		return users
	}
	out := []string{}
	seen := map[string]bool{}
	for _, cred := range pairs {
		if u, _, ok := splitCred(cred); ok && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func pwdsOrPairs(pwds []string, pairs []string) []string {
	if pairs == nil {
		return pwds
	}
	out := []string{}
	seen := map[string]bool{}
	for _, cred := range pairs {
		if _, p, ok := splitCred(cred); ok && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// humanDuration keeps short estimates readable: "250ms", not "0s".
func humanDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(10 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// lockRegistry tracks accounts the server reported as locked out. Once an
// account is locked, every remaining attempt for that username is dropped:
// more attempts only extend the lockout, and a locked account refuses even
// the correct password, so there is nothing left to gain.
type lockRegistry struct {
	mu      sync.Mutex
	ctxs    map[string]context.Context
	cancels map[string]context.CancelFunc
	locked  map[string]string // key -> username as written
}

func newLockRegistry() *lockRegistry {
	return &lockRegistry{
		ctxs:    map[string]context.Context{},
		cancels: map[string]context.CancelFunc{},
		locked:  map[string]string{},
	}
}

func lockKey(user string) string { return strings.ToLower(user) }

// ctxFor returns the context governing this username. It is cancelled the
// first time the account is reported locked, which aborts whatever probe
// for that user is in flight.
func (lr *lockRegistry) ctxFor(user string) context.Context {
	k := lockKey(user)
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if ctx, ok := lr.ctxs[k]; ok {
		return ctx
	}
	ctx, cancel := context.WithCancel(context.Background())
	lr.ctxs[k], lr.cancels[k] = ctx, cancel
	return ctx
}

func (lr *lockRegistry) isLocked(user string) bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	_, ok := lr.locked[lockKey(user)]
	return ok
}

// markLocked records a lockout and reports whether this is the first time
// it is seen, so the warning prints once per account rather than once per
// queued attempt.
func (lr *lockRegistry) markLocked(user string) bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	k := lockKey(user)
	if _, ok := lr.locked[k]; ok {
		return false
	}
	lr.locked[k] = user
	if cancel, ok := lr.cancels[k]; ok {
		cancel()
	}
	return true
}

func (lr *lockRegistry) lockedCount() int {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return len(lr.locked)
}

// hostGate caps how many probes may run against one target at a time.
// A Windows RDP listener folds under a flood of parallel handshakes —
// measured against a Windows 7 VM, -t 300 on a single host made 74% of the
// attempts die as transport errors before authentication even started —
// so per-host concurrency is limited independently of -t.
type hostGate struct {
	mu    sync.Mutex
	slots map[string]chan struct{}
	size  int
}

func newHostGate(size int) *hostGate {
	return &hostGate{slots: map[string]chan struct{}{}, size: size}
}

func (g *hostGate) slot(key string) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.slots[key]
	if !ok {
		s = make(chan struct{}, g.size)
		g.slots[key] = s
	}
	return s
}

func (g *hostGate) acquire(key string) { g.slot(key) <- struct{}{} }

func (g *hostGate) release(key string) {
	select {
	case <-g.slot(key):
	default: // never block: a missing slot is a bug, not a hang
	}
}

// hostKey is the concurrency key for a target: the address actually
// dialled, so "1.2.3.4" and "1.2.3.4:3389" share one cap while two ports
// on one machine are treated as two targets.
func hostKey(target string) string {
	h, p := hostPort(target)
	return h + ":" + p
}

// bareUser drops the domain part of "DOMAIN\user" for display.
func bareUser(user string) string {
	if i := strings.LastIndex(user, `\`); i >= 0 {
		return user[i+1:]
	}
	return user
}

// resultSink wraps the CSV/file outputs.
type resultSink struct {
	f           *os.File
	w           *csv.Writer
	quiet       bool
	debug       bool
	showFailed  bool
	noPasswords bool
}

func newResultSink(path string, quiet, debug, showFailed, noPasswords bool) *resultSink {
	rs := &resultSink{quiet: quiet, debug: debug, showFailed: showFailed, noPasswords: noPasswords}
	if path != "" {
		fp, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fatal("output: %v", err)
		}
		st, err := fp.Stat()
		if err == nil && st.Size() == 0 {
			fp.WriteString("host,port,user,password,status,duration_ms,timestamp\n")
		}
		rs.f = fp
		rs.w = csv.NewWriter(fp)
	}
	return rs
}

func (rs *resultSink) Close() {
	if rs.w != nil {
		rs.w.Flush()
	}
	if rs.f != nil {
		rs.f.Close()
	}
}

// hostPort splits a "host:port" target back apart for the CSV.
func hostPort(h string) (string, string) {
	if host, port, err := net.SplitHostPort(h); err == nil {
		return host, port
	}
	return h, "3389"
}

// csvPassword is the password column: the real secret on a hit, masked
// otherwise unless the operator explicitly asked to keep failed ones.
func (rs *resultSink) csvPassword(r result) string {
	if rs.noPasswords {
		return "<masked>"
	}
	if r.status == rdp.StatusSuccess || rs.showFailed {
		return r.j.Pass
	}
	return "<masked>"
}

func (rs *resultSink) emit(r result) {
	user := bareUser(r.j.User)
	host, port := hostPort(r.j.Host)
	target := net.JoinHostPort(host, port)

	// CSV: everything about the attempt, including how long it took and
	// when it happened, so a batch can be diffed against a later one.
	if rs.w != nil {
		rs.w.Write([]string{
			host,
			port,
			user,
			rs.csvPassword(r),
			r.status.String(),
			strconv.FormatInt(r.duration.Milliseconds(), 10),
			r.start.UTC().Format(time.RFC3339),
		})
		rs.w.Flush()
	}

	switch {
	case r.status == rdp.StatusLockedOut:
		// Loud by design: this one must survive -q.
		fmt.Printf("[!] %s  user=%s  status=LOCKED_OUT  (stopping this user)\n", target, user)
	case r.status == rdp.StatusSuccess:
		fmt.Printf("[+] %s  user=%s  password=%s  time=%s\n",
			target, user, r.j.Pass, humanDuration(r.duration))
		if rs.debug && r.err != nil {
			fmt.Fprintf(os.Stderr, "    detail: %v\n", r.err)
		}
	case r.status == rdp.StatusNoNLA && !rs.quiet:
		fmt.Printf("[~] %s  user=%s  status=NO-NLA  (no NLA — not protocol-verifiable)\n", target, user)
	case !rs.quiet && (r.status == rdp.StatusError || r.status == rdp.StatusRefused):
		line := fmt.Sprintf("[~] %s  user=%s  status=%s", target, user, r.status)
		if r.err != nil {
			line += fmt.Sprintf("  detail=%v", r.err)
		}
		fmt.Println(line)
	case !rs.quiet:
		line := fmt.Sprintf("[-] %s  user=%s  status=%s", target, user, r.status)
		if rs.debug && r.err != nil {
			line += fmt.Sprintf("  detail=%v", r.err)
		}
		fmt.Println(line)
	}
}

// splitCred handles "user:pass" as well as "DOMAIN\user:pass".
func splitCred(s string) (user, pass string, ok bool) {
	s = strings.TrimSpace(s)
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// loadLines reads a list file ("-" = stdin), dropping blanks, comment
// lines and the UTF-8 BOM. The work lives in internal/cli so that every
// list this tool accepts uses one format; an empty result is an error
// there, and the caller names the flag that asked for the file.
func loadLines(path string) ([]string, error) {
	return cli.ReadLines(path)
}

// countCredParts counts the distinct usernames and passwords inside a
// legacy 'user:pass' list, for the batch summary only. The pairs themselves
// keep their exact meaning; nothing is crossed here.
func countCredParts(pairs []string) (int, int) {
	var names, secrets []string
	for _, cred := range pairs {
		u, p, ok := splitCred(cred)
		if !ok {
			continue
		}
		names = append(names, u)
		secrets = append(secrets, p)
	}
	return len(cli.Dedupe(names, true)), len(cli.Dedupe(secrets, false))
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "rdpdash: "+f+"\n", a...)
	os.Exit(exitFatal)
}

// usageError reports a problem with how the command was written and stops
// before a single connection is made. Exit code 2, matching usage(): a
// refusal is not a probe that failed.
func usageError(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "rdpdash: "+f+"\n", a...)
	os.Exit(exitUsage)
}

// banner is printed on every run, before any validation, so that no
// invocation — successful or refused — leaves the process without the
// authorization notice. The second line is deliberately kept verbatim: it
// is part of the tool's contract with its operator, worded the same way as
// rdp-audit's banner.
const bannerBody = ` FOR AUTHORIZED TESTING ONLY. Unauthorized access is illegal.
 Use only against systems you own or have explicit written permission to test.
 This tool performs RDP authentication attempts (NLA/CredSSP).
======================================================================`

func printBanner() {
	fmt.Printf("=============================== %s ===============================\n", buildTag)
	fmt.Println(bannerBody)
}

// buildTagFromArgs peeks for --build-tag before flag.Parse runs, because
// the banner carries the tag and has to print first (so that -h shows it
// too). Both "-build-tag value" and "-build-tag=value" are recognised.
func buildTagFromArgs(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		if name != "-build-tag" && name != "--build-tag" {
			continue
		}
		if hasVal {
			return val, true
		}
		if i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func usage() {
	printUsage()
	os.Exit(exitUsage)
}

// printUsage is also flag.Usage, so -h prints exactly the help a refused
// invocation prints (the banner precedes both).
func printUsage() {
	fmt.Fprintln(os.Stderr, `rdpdash: need targets AND credentials.

  targets
  -p IP       one target IP/hostname (also --ip)
  -list FILE  file with target IPs (single-dash spelling of --ip-list)
  -f FILE     targets, one host[:port] per line ('-' for stdin)
  target      one or more positional targets

  credentials
  -u USER     one username (also --username)
  -ul FILE    file with usernames (single-dash spelling of --user-list)
  -pl FILE    file with passwords (single-dash spelling of --password-list)
  -U USER -P PASS   single credential (legacy, instead of -u/-pl)
  -c FILE     credentials, one 'user:pass' per line (legacy)

  -d DOMAIN   default domain for bare usernames
  -t N        parallel workers (default 2×CPU)
  -per-host N max concurrent probes per target host (default 5, max 32)
  -timeout N  seconds per probe
  -o FILE     append results to CSV (host,port,user,password,status,
              duration_ms,timestamp)
  -hits-file FILE  successful credentials, one per line (default hits.txt)
  --dry-run   print the plan and exit without connecting
  --build-tag S  banner tag (default "rdpdash", also -ldflags -X)
  -show-failed-passwords  keep failed passwords in the CSV
  -no-passwords  always mask the CSV password column
  -q          quiet: successes only
  -v          verbose error details

  exit codes
  0 nothing found, 2 refused command line, 3 credential accepted,
  4 every attempt unreachable, 5 an account was locked out

examples:
  rdpdash -f targets.txt -c creds.txt -t 64
  rdpdash -p 192.168.174.133 -u ALIREZA -pl passwords.txt
  rdpdash -list ips.txt -ul users.txt -pl passwords.txt
  rdpdash --dry-run -list ips.txt -ul users.txt -pl passwords.txt
  echo scope.local | rdpdash -c creds.txt

NOTE:
  -list, -ul and -pl are the single-dash spellings of
  --ip-list, --user-list and --password-list.`)
}

// reorderArgs moves positional (non-flag) arguments to the end so flag.Parse()
// can parse flags regardless of argument positioning on the command line.
// A value-taking flag always consumes the following token, even when it
// starts with '-' (passwords such as "-secret" must not be mistaken for
// flags).
func reorderArgs(args []string) []string {
	var flags, pos []string
	takesVal := map[string]bool{
		"-f": true, "--f": true,
		"-c": true, "--c": true,
		"-U": true, "--U": true,
		"-P": true, "--P": true,
		"-d": true, "--d": true,
		"-t": true, "--t": true,
		"-timeout": true, "--timeout": true,
		"-o": true, "--o": true,
		"-p": true, "--p": true,
		"-u": true, "--u": true,
		"-ip": true, "--ip": true,
		"-username": true, "--username": true,
		"-ip-list": true, "--ip-list": true,
		"-user-list": true, "--user-list": true,
		"-password-list": true, "--password-list": true,
		"-per-host": true, "--per-host": true,
		"-hits-file": true, "--hits-file": true,
		"-build-tag": true, "--build-tag": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			// -U user vs -U=user
			if takesVal[arg] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, arg)
		}
	}
	return append(flags, pos...)
}
