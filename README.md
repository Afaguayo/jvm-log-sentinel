# jvm-log-sentinel

[![CI](https://github.com/Afaguayo/jvm-log-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Afaguayo/jvm-log-sentinel/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://adoptium.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A command-line authentication log analyzer, written in Java, that flags
**brute-force** bursts and **credential-stuffing** sprays from sshd and
Apache/nginx access logs.

## Why

Most small servers never look at `/var/log/auth.log` until something has
already gone wrong. This tool gives a cheap, offline, no-dependency way to
answer "did anyone try to break in?" from a log file, a cron job, or a CI
step — without shipping logs anywhere.

## How it works

1. **Parse** — `LogParser` normalizes two formats into a common `AuthEvent`
   (timestamp, source IP, username, success/failure):
   - sshd syslog lines (`Failed password for ... from ... port ...`,
     `Accepted ... for ... from ...`)
   - Apache/nginx combined access log lines, treating `401`/`403` as failed
     auth and `2xx` as success.
2. **Cluster** — `BruteForceDetector` groups failed attempts by source IP and
   runs a sliding-window scan (two-pointer, O(n) per IP) to find the densest
   burst of failures within a configurable time window.
3. **Classify** — a burst against few usernames is `BRUTE_FORCE`; a burst
   touching many distinct usernames from one IP is `CREDENTIAL_STUFFING`.
4. **Report** — findings and a top-offenders table are printed as text or
   JSON, with a non-zero exit code when something was found (so it plugs
   into cron + alerting easily).

## Build

Requires JDK 17+ and Maven.

```bash
mvn package
```

This produces `target/jvm-log-sentinel.jar` (a self-contained
jar-with-dependencies — there are no runtime dependencies today, but this
keeps future ones from requiring a classpath).

## Usage

```bash
java -jar target/jvm-log-sentinel.jar --input /var/log/auth.log
```

```
jvm-log-sentinel report
========================
Events parsed:   13
Lines unparsed:  0
Findings:        2

Suspicious activity
--------------------
- [CREDENTIAL_STUFFING] ip=198.51.100.9 failed=6 distinct_users=6 window=2026-06-14T03:25 -> 2026-06-14T03:25:25 users=[alice, bob, carol, dave, erin, frank]
- [BRUTE_FORCE] ip=203.0.113.5 failed=6 distinct_users=1 window=2026-06-14T03:22:01 -> 2026-06-14T03:22:16 users=[root]

Top offending IPs by failed attempts
-------------------------------------
198.51.100.9         6
203.0.113.5          6
```

A ready-made sample log is included at
`src/main/resources/samples/auth.log` — try it with:

```bash
java -jar target/jvm-log-sentinel.jar --input src/main/resources/samples/auth.log
```

### Options

| Flag | Default | Meaning |
|---|---|---|
| `--input <file>` | *(required)* | Log file to analyze |
| `--window-minutes <n>` | 5 | Sliding window size |
| `--fail-threshold <n>` | 5 | Failed attempts from one IP in the window to flag brute force |
| `--user-threshold <n>` | 6 | Distinct usernames from one IP in the window to flag credential stuffing |
| `--json` | off | Emit JSON instead of text |
| `--out <file>` | stdout | Write the report to a file |

Exit codes: `0` no findings, `2` findings detected, `1` usage error.

## Tests

```bash
mvn test
```

9 JUnit 5 tests cover log parsing (both formats, edge cases like `invalid
user`) and detection (brute force, credential stuffing, and that a single
successful login never gets flagged).

## Limitations

- Syslog timestamps have no year, so the current year is assumed — fine for
  live logs, slightly wrong for very old archived ones.
- The sliding-window scan is per-IP, not globally distributed; a
  low-and-slow attack spread across many IPs below the per-IP threshold
  won't be caught by this tool alone.
- Not a replacement for `fail2ban` or a real SIEM — this is an analysis and
  learning tool, not a blocking mechanism.

## License

MIT — see [LICENSE](LICENSE).
