# rdpdash

A parallel RDP credential checker written in Go. It probes targets over
RDP's Network Level Authentication flow (CredSSP v2 with NTLMv2 and
sealed public-key binding), reporting which username/password pairs the
server accepts.

## Build

```sh
# Current OS / native
go build -o rdpdash .

# Linux x64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o rdpdash-linux-amd64 .

# Windows x64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o rdpdash-windows-amd64.exe .
```

## Usage

```sh
# targets + credentials files (legacy pair mode: each user:pass as written)
rdpdash -f targets.txt -c creds.txt -t 64 -o results.csv

# single credential
rdpdash -f targets.txt -U svc.scan -P 'S3cr3t!' -o results.csv

# stdin targets
echo 10.0.0.5:3389 | rdpdash -c creds.txt

# one target, one username, a password list (cross product)
rdpdash -p 192.168.174.133 -u ALIREZA -pl passwords.txt

# three files: every target × every username × every password
rdpdash -list ips.txt -ul users.txt -pl passwords.txt
```

### Input formats

- Targets: `host` or `host:port`, one per line (`#` comments supported).
- Credentials: `user:pass`, one per line. `DOMAIN\user:pass` is accepted.
- List files (`-list`, `-ul`, `-pl`, and also `-f`/`-c`): one entry per
  line, `#` comments and blank lines ignored, UTF-8 BOM stripped, entries
  trimmed. An empty file is an error that names the flag.
- With the new flags the run is a cross product: every target is probed
  with every username and every password. Targets/usernames deduplicate
  case-insensitively, passwords case-sensitively; a `-c` file keeps its
  exact pair meaning and is never crossed.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p` (also `--ip`) | — | one target IP/hostname |
| `-list` (also `--ip-list`) | — | file with target IPs |
| `-u` (also `--username`) | — | one username |
| `-ul` (also `--user-list`) | — | file with usernames |
| `-pl` (also `--password-list`) | — | file with passwords |
| `-f` | — | targets file (`-` for stdin) |
| `-c` | — | credentials file (pairs, used as written) |
| `-U` / `-P` | — | single username / password (legacy) |
| `-d` | — | default domain for bare usernames |
| `-t` | 2×CPU | parallel workers |
| `-timeout` | 6 | per-probe timeout (seconds) |
| `-o` | — | append results to a CSV file |
| `-q` | false | quiet (successes only) |
| `-v` | false | verbose error details |
| `-per-host N` | 5 | max concurrent probes per target host (1..32) |
| `-hits-file FILE` | hits.txt | accepted credentials, one per line (`""` disables) |
| `-show-failed-passwords` | false | keep failed passwords in the CSV |
| `-no-passwords` | false | mask all passwords in the CSV |
| `--dry-run` | false | print the plan, open no connections |
| `--build-tag TAG` | rdpdash | banner tag (also `-ldflags "-X main.buildTag=..."`) |

`-list`, `-ul` and `-pl` are single-dash spellings of `--ip-list`,
`--user-list` and `--password-list`; they are translated before parsing,
so both spellings work. Mixing a new flag with the legacy flag that
supplies the same list (`-u` with `-U`, `-pl` with `-c` or `-P`) is
refused as ambiguous with exit code 2.

## Protocol coverage

- CredSSP v2 (MS-CSSP §3.1.5) over TLS with NTLMv2 inside:
  - `NEGOTIATE` / `CHALLENGE` / `AUTHENTICATE` in the `negoTokens` field
    (raw NTLMSSP tokens, SPNEGO-wrapped tokens are also parsed);
  - the client's last token is sent together with `pubKeyAuth`: the
    server certificate's `SubjectPublicKey`, sealed with the NTLM session
    key (MS-NLMP RC4 + HMAC-MD5 signing/sealing);
  - the server's `pubKeyAuth` answer (public key + 1) is verified; it is
    the proof that NTLM authentication succeeded, i.e. the credentials
    are valid. A rejected logon aborts the connection with a TLS alert
    instead;
  - the delegated `TSCredentials` are then sent sealed in `authInfo`.
- All CredSSP structures use the real DER shapes (`[0]` version,
  `[1]` negoTokens, `[2]` authInfo, `[3]` pubKeyAuth, `[4]` errorCode),
  and TSCredentials carry the domain, user and password as UTF-16LE
  OCTET STRINGs in the order required by the spec.
- Message sealing (key derivation, RC4 keystream, HMAC-MD5 checksum and
  sequence numbers) is pinned by test vectors produced with an
  independent implementation.
- `DOMAIN\user` overrides `-d`; bare usernames use the `-d` default.
- Servers that negotiate TLS-only or standard RDP security are reported
  as `NO-NLA` (credentials cannot be verified at the protocol level).
- Kerberos (Kerberos-v5 mechType over SPNEGO) is not wired in; hosts that
  require pure-Kerberos NLA are reported as failed.

> The CredSSP client is exercised end-to-end against the in-process fake
> NLA server in the test suite, including pubKeyAuth binding and the
> sealed credential payload. There is no live Windows host in the test
> environment, so a `SUCCESS` result is only as trustworthy as the
> target's protocol behaviour.

## Output

Console lines are prefixed with `[+]` (accepted), `[-]` (rejected) and
`[~]` (non-verifiable). CSV columns: `host,port,user,password,status,duration_ms,timestamp`.

Every run ends with a batch summary on stderr:

```text
Done: N targets, M users, K passwords, T attempts, H hits, Ss
```

where `T` is the number of probes actually run (targets × users ×
passwords in cross mode) and `S` the elapsed seconds.

## Authorization

The authorization banner and disclaimer print on every run, before any
validation, so no invocation leaves the process without them.

This tool is intended for authorized security assessments only. Run it
against systems you own or have explicit written permission to test.
Unauthorized use against systems you do not own may be illegal.

## Complete result display

Every accepted credential is shown on the console, with the password:

    [+] 192.168.174.133:3389  user=ALIREZA  password=12345678  time=1s

Every failure is printed without the password:

    [-] 192.168.174.133:3389  user=ALIREZA  status=FAIL

A lockout is loud and stops the user:

    [!] 192.168.174.133:3389  user=ALIREZA  status=LOCKED_OUT  (stopping this user)

At the end of a run a multi-line summary lists every hit:

    ================ BATCH SUMMARY ================
    Targets:             1
    Users:               70
    Passwords:           70
    Total combinations:  4900
    Attempts:            4900 (0 skipped, 0 errors)
    Hits (SUCCESS):      1
    Failures (FAIL):     4880
    Locked out:          0
    Refused:             19
    Errors:              0
    Duration:            259s (0.1s per attempt avg)

    VALID CREDENTIALS:
      192.168.174.133:3389  ALIREZA:12345678  (found at 2026-10-30T14:25:12Z)
    ===============================================

### CSV columns

    host,port,user,password,status,duration_ms,timestamp

`password` is the real secret on SUCCESS; `<masked>` otherwise, unless
`-show-failed-passwords` is set. `-no-passwords` masks every row,
including hits.

### Hits file

`-hits-file FILE` (default `hits.txt`) writes one line per accepted
credential:

    192.168.174.133:3389  ALIREZA:12345678  2026-10-30T14:25:12Z

Set `-hits-file ""` to disable it.

## Account lockout detection

A server that enforces account-lockout policy answers a rejected logon
with NTSTATUS `STATUS_ACCOUNT_LOCKED_OUT` (`0xC0000234`). rdpdash
recognises it as `LOCKED_OUT`, cancels every queued attempt for that
username, and keeps probing other users. The run exits with code 5 if
any account was locked.

Probabilities and side effects:

- rdpdash never retries a locked account, even with a correct password
  (a locked account refuses it anyway).
- The other usernames in the batch continue unaffected.
- The warning is printed once per account, not once per attempt.

## Per-host concurrency (-per-host)

`-t N` is a global worker count. On a single Windows host a flood of
parallel handshakes makes the RDP listener drop connections before
authentication starts: measured on a Windows 7 VM, `-t 300` produced
74% transport errors. `-per-host N` (default 5, range 1..32) caps the
concurrent probes against any one target. Effective parallelism is
`min(-t, -per-host)` per host.

## Dry run (--dry-run)

`--dry-run` prints the plan (targets, users, passwords, combinations,
estimated time, first and last 3 probes) and exits without opening a
connection. Use it to verify list files before a real run.

## Password visibility flags

- `-show-failed-passwords` (default false): write failed attempts'
  passwords to the CSV. Useful for lab analysis, risky in production.
- `-no-passwords` (default false): mask every password, including
  successful ones. Use when the CSV must be shared.

## Windows Defender false positives

Windows Defender flags the freshly built binary as potentially unwanted
software because of the credential-testing pattern. It is not malware.
To build without triggering the heuristic:

    go build -ldflags="-s -w" -o rdpdash.exe .

If it still triggers, add the project directory to the exclusion list:
Settings -> Windows Security -> Virus & threat protection ->
Manage settings -> Exclusions -> Add an exclusion -> Folder.

## New flags (summary)

| Flag | Default | Description |
|------|---------|-------------|
| `-per-host N` | 5 | max concurrent probes per host (1..32) |
| `-hits-file FILE` | hits.txt | accepted credentials, one per line ("" disables) |
| `-show-failed-passwords` | false | keep failed passwords in CSV |
| `-no-passwords` | false | mask all passwords in CSV |
| `--dry-run` | false | print plan, no connections |
| `--build-tag TAG` | rdpdash | banner tag (also `-ldflags "-X main.buildTag=..."`) |

## Exit codes

The verdict of a run is a number so scripts can branch on it without
scraping the summary.

| Code | Meaning |
|------|---------|
| 0 | finished, nothing found, nobody locked out |
| 1 | internal error (bad output file, ...) |
| 2 | the command line was refused before probing |
| 3 | at least one credential was accepted |
| 4 | every attempt was an error or a refusal |
| 5 | at least one account was locked out during the run |
