# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

log_anonimizer is a single Go binary for SOC/IR teams: `-a` replaces sensitive values in logs with tokens (`HOST_0001`, `USER_0003`, `EXTIP_0002`), `-d` restores them using an encrypted `.anonmap`, `-verify` checks output, `-show` prints the token table. With no arguments it starts a terminal wizard. User-facing docs are in README.md; the README is also edited directly on GitHub, so `git pull --ff-only` before touching it.

## Commands

```bash
go test ./...                                         # all tests (unit, end-to-end, CLI, wizard)
go test ./internal/anon -run TestKeyValue             # one test
go test ./internal/anon -run 'TestIPv4/with_port'     # one table case (spaces in names become _)
go vet ./... && gofmt -l cmd internal
GOOS=windows GOARCH=amd64 go vet ./...                # Windows-only code (internal/tui/console_windows.go)
go build -o log_anonimizer ./cmd/log_anonimizer
./scripts/build.sh                                    # dist/log_anonimizer_<ver>_<os>_<arch> + SHA256SUMS
```

If the Go module proxy is unreachable, the dependencies are usually in the module cache: prefix with `GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`.

CI (`.github/workflows/ci.yml`) runs vet and the tests on Linux, Windows and macOS, plus gofmt and `examples/regenerate.sh` (the outputs must not change).

Releases: bump `const Version` in `internal/app/app.go`, commit and push, then push the tag `vX.Y.Z`. `.github/workflows/release.yml` checks the tag against `Version`, runs the tests, builds with `scripts/build.sh` on the newest Go 1.26 patch (`go.mod`'s `go 1.26.0` is only the minimum; building with it would miss security fixes) and creates a **draft** release with the binaries and `SHA256SUMS`; write the notes and publish it from GitHub (or `gh release edit vX.Y.Z --draft=false --notes-file …`). By hand instead: `scripts/build.sh` on a clean tree (binaries embed `vcs.revision`/`vcs.modified`; check with `go version -m dist/<file>`), then `gh release create vX.Y.Z dist/log_anonimizer_X.Y.Z_* dist/SHA256SUMS --target <commit>`.

Regenerate `examples/` after detector changes with `./examples/regenerate.sh`: it rewrites the outputs, `show.txt`, the plain `sample.anonmap` and `sample.encrypted.anonmap` (passphrase `example-passphrase`), and fails unless both maps restore `sample.log` exactly. Maps record input/output paths as typed, so run it from the repo, never with absolute paths that would publish a home folder.

## Data rules

- `Sample_Logs/` contains real customer logs (git-ignored, as is `Simple_Logs/`). Never commit, paste or quote values from it, including in tests and code comments. Test data must be fictional (`acme`, `*.example`, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- To check behaviour on the real data, write output and an unencrypted map (`-no-encrypt`) to a scratch folder, run `-d`, and compare with the original. Expect `verify OK` and no differences except letter case (see below). The LogRhythm CSV takes ~10 s; the KAPE folder `Sample_Logs/1` takes 3–5 min, so run it in the background.

## Architecture

Packages: `cmd/log_anonimizer` (flag parsing, `run(args, env)` is testable) → `internal/app` (the four operations, passphrase prompting with 3 retries, output formatting; shared by CLI and wizard) → `internal/anon` (detection, engine, restore, verify) → `internal/vault` (token map + encrypted file) and `internal/profile` (YAML options). `internal/tui` is the wizard on raw terminal mode with `x/term`; `Options.Reader` replaces the terminal so tests can script keys.

### Detection (`internal/anon/scanner.go`, `detectors.go`)

- `Scanner.find` runs every detector on the **original** text and collects candidate spans. Each span is a list of parts: literal text, or `(kind, value)`. A composite span such as `HOST.DOMAIN`, `DOMAIN\USER` or `USER%40DOMAIN` is one span. `resolve` keeps the longest spans, ties broken by priority (`prioContext` > … > `prioTerm`), with no overlaps. Tokens are written only when rendering, so tokenized text is never scanned again.
- Fields with known meaning go through `LearnField`/`ApplyField` with a `FieldKind`. The kind comes from CSV header names (`columnKinds` in `files.go`, including LogRhythm columns) or IIS `#Fields`. `FieldURL` and `FieldUserAgent` switch off detectors that misfire on attacker input (`urlMode`/`uaMode`).
- Domains are replaced only when internal: configured `internal_suffixes`, domains learned from identity contexts (`<Computer>`, syslog host, `FieldHost`, e-mail and `DOMAIN\user` outside URLs), or anything containing a `sensitive_terms` entry (`internalDomain`). Unknown external domains are kept as IOCs, and the engine reports them as `KeptDomains`. `FieldHostRemote` and URL contexts never teach new internal domains.
- Attacker input is evidence and is kept on purpose: `invalid user X`, probed URL paths, bot contact e-mails, `host:80@domain`. Version strings (`Chrome/120.0.0.0`, `rv:1.8.0.6`, GAC folders) are not IPs (`isVersion`). Several heuristics deal with `%XX` encoding and escaped `\r\n`/`\t` text. Each was added for a real case, and each case is pinned in `detect_test.go`.
- `allow.go` holds the built-in allow lists. `commonWords` keeps generic words found in user/host fields from being searched for in free text.
- Numbers (`numbers.go`) must prove what they are, because logs are full of timestamps and IDs: cards pass Luhn and a brand prefix/length (nothing starting with 1, so epoch times and snowflake IDs never match); Thai national IDs pass the check digit and are grouped `1-2345-67890-12-1` or labelled (`natIDWords`), since a bare 13-digit number may be milliseconds; phones have a Thai grouping or a `+country` prefix. `detectNumbers` walks each digit run once (regexes here cost 30× more on real data); time it on the LogRhythm CSV after changes.
- `keys.go`: credentials recognisable by shape (JWT, AWS/GitHub/Slack/Google/Stripe keys), private keys and connection strings. A key file spans lines, so `Scanner.inKey` carries state from a BEGIN line to the END line; the engine and verify call `ResetLines` per file. Test strings that look like real tokens are split (`"gh" + "p_" + …`) so GitHub push protection does not block the push.

### Engine (`engine.go`)

`Anonymize`: sniff files (binary is skipped) → `choosePrefix` (adds `ANON_` etc. if the input already contains token-like text) → learn passes (repeated while `ctxVersion` changes, at most `maxLearnPasses`; words that only contain a sensitive term are named NAME at the end of a pass via `SetLearning`) → `RebuildDict` (Aho-Corasick over learned values that pass `dictValue`) → write output (rewritten once if the dictionary grew) → `findLeaks` verify. Folder mode anonymizes relative paths too and writes `ANONYMIZATION_REPORT.txt`. CSV goes through `csvScanner`/`writeCSVFields`, which keep per-field quoting and line endings, so files round-trip byte for byte apart from merged letter case.

### Tokens and restore (`internal/vault`, `internal/anon/restore.go`)

- `Key` normalizes values so case variants of host/user/domain/org share one token, and card, ID and phone numbers are keyed by their digits (`4111 1111…` and `4111-1111…` share one). `-d` returns the first spelling seen, so case-only differences after a round trip are expected. Secrets are case-sensitive. New kinds go in `vault.Kinds` and `prefixes` (the token regexp is built from them), `kindLabels` in `app/show.go`, the profile toggles and `Marshal`, and the wizard's `toggleItems`. An older binary opens a map with new kinds but its token regexp does not know them, so its `-d` silently leaves those tokens in place: say so in the release notes.
- `anon.RestoreString` finds tokens with `vault.TokenPattern`, `vault.IsTokenStart` (no letter or digit before, except after `%XX` or a `\n`/`\r`/`\t` escape) and `Vault.Resolve` (longest known prefix when digits follow).
- **Invariant:** any change to detector boundaries must still emit tokens that `-d` can find. Never put a token directly after a letter or digit. Digits after a token are fine. `dictBoundary`/`ipBoundary` and `boundaryOK` in `verify.go` must stay consistent with each other.
- The map file is a JSON envelope, plain or AES-256-GCM with an Argon2id key, written with 0600 permissions. Test packages that save encrypted maps lower `vault.KDFTime/KDFMemory/KDFThreads` in `TestMain`.

### Profiles

The first `-a` run without `-p` creates `default.yaml` in the profile dir (`LOGANON_PROFILE_DIR` overrides it; tests set it to a temp dir) and the CLI prints yellow warnings for a missing `-p` and empty `sensitive_terms`. `profile.Marshal` writes the commented template by hand: if you add a field to `Profile`, also add it to `Marshal`, or saved profiles will drop it.
