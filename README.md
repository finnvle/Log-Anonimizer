# Log Anonimizer

Replace the values that identify people, machines and organisations in logs (IP addresses,
hostnames, accounts, domains, e-mail, MAC, SIDs, passwords and tokens …) with tokens such as
`HOST_0001`, `USER_0003` or `IP_0012` before you hand the logs to someone else: a vendor, an
external IR team, an AI model. Later, turn the tokens back into the real values with the map
file that only you keep.

Built for SOC and incident-response work:

- **One file, nothing to install.** Static binaries for Windows, Linux and macOS, on amd64 and arm64.
- **Consistent tokens.** The same value gets the same token on every line, in every file, and in later runs that reuse the map, so timelines and correlation still work.
- **Encrypted map.** The map is protected with a passphrase by default (AES-256-GCM, key from Argon2id).
- **Built-in verification.** Every run checks that no known original value is left in the output.
- **CLI and wizard.** Run it with no arguments for an interactive wizard with checkboxes, or use flags in scripts.
- **See the mapping.** `-show` prints which token stands for which real value, for a whole map or only for the tokens in one file.

```
before:  Oct 10 08:15:02 fw-edge01 sshd[2211]: Accepted password for somchai.k from 203.0.113.45 port 51522 ssh2
after:   Oct 10 08:15:02 HOST_0001 sshd[2211]: Accepted password for USER_0001 from EXTIP_0001 port 51522 ssh2
```

## Contents

- [Get the binary](#get-the-binary)
- [Usage](#usage)
  - [Windows](#windows)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Commands and options](#commands-and-options)
  - [See what a token stands for: `-show`](#see-what-a-token-stands-for--show)
- [Example: anonymize, then de-anonymize](#example-anonymize-then-de-anonymize)
- [What gets replaced](#what-gets-replaced)
- [Supported input](#supported-input)
- [The map file](#the-map-file)
- [Profiles](#profiles)
- [Limitations](#limitations)
- [Development](#development)

## Get the binary

Build it with [Go](https://go.dev/dl/) 1.26 or newer, on any OS:

```bash
git clone https://github.com/finnvle/Log-Anonimizer.git
cd Log-Anonimizer
go build -o log_anonimizer ./cmd/log_anonimizer        # this machine
./scripts/build.sh                                       # every OS/CPU into dist/ + SHA256SUMS
```

`scripts/build.sh` cross-compiles everything from one machine (CGO is off):

| File in `dist/` | Runs on |
|---|---|
| `log_anonimizer_<ver>_windows_amd64.exe` | Windows 10/11, Server 2016+ (x64) |
| `log_anonimizer_<ver>_windows_arm64.exe` | Windows on ARM |
| `log_anonimizer_<ver>_linux_amd64` | Linux x86-64 (any distribution, static binary) |
| `log_anonimizer_<ver>_linux_arm64` | Linux ARM64 (Graviton, Raspberry Pi 4/5 64-bit …) |
| `log_anonimizer_<ver>_darwin_arm64` | macOS on Apple Silicon |
| `log_anonimizer_<ver>_darwin_amd64` | macOS on Intel |

Copy the file for your platform to the analysis machine and rename it to `log_anonimizer`
(`log_anonimizer.exe` on Windows). The examples below use that name.

## Usage

The wizard is the easiest start. It asks for the input, lets you tick what to anonymize,
asks for organisation names, sets up the map, and at the end prints the equivalent command
line for scripts.

| Key | Action |
|---|---|
| ↑ / ↓ | move |
| Space | tick / untick |
| `a` | tick all |
| Tab | complete a path |
| Enter | confirm |
| Ctrl+C | quit |

### Windows

Use PowerShell in Windows Terminal. The legacy console also works.

```powershell
# files downloaded from the internet may be blocked by SmartScreen
Unblock-File .\log_anonimizer.exe

# interactive wizard
.\log_anonimizer.exe

# anonymize a file or a whole KAPE / triage folder
.\log_anonimizer.exe -a C:\cases\4711\LogRhythm_export.csv
.\log_anonimizer.exe -a C:\cases\4711\kape\ -p customer-a

# de-anonymize: the anonymized log, or a report that came back with tokens in it
.\log_anonimizer.exe -d C:\cases\4711\LogRhythm_export.anon.csv
.\log_anonimizer.exe -d .\vendor_report.md -m C:\cases\4711\LogRhythm_export.anonmap

# check an anonymized file before sending it
.\log_anonimizer.exe -verify C:\cases\4711\LogRhythm_export.anon.csv -m C:\cases\4711\LogRhythm_export.anonmap

# which real value is behind each token?
.\log_anonimizer.exe -show C:\cases\4711\LogRhythm_export.anon.csv
.\log_anonimizer.exe -show C:\cases\4711\LogRhythm_export.anonmap -find somchai

# passphrase for scripts (otherwise you are asked)
$env:LOGANON_PASSPHRASE = "a long passphrase"
```

In `cmd.exe`, use `log_anonimizer.exe -a C:\cases\export.csv` and `set LOGANON_PASSPHRASE=...`.

### Linux

```bash
chmod +x log_anonimizer
./log_anonimizer                                   # wizard (also works over SSH)
./log_anonimizer -a /cases/4711/auth.log           # -> auth.anon.log + auth.anonmap
./log_anonimizer -a /cases/4711/kape/ -o /cases/4711/share/kape.anon
./log_anonimizer -d /cases/4711/auth.anon.log      # -> auth.restored.log
./log_anonimizer -verify /cases/4711/auth.anon.log -m /cases/4711/auth.anonmap
./log_anonimizer -show /cases/4711/auth.anon.log           # tokens in this file and their real values

export LOGANON_PASSPHRASE='a long passphrase'      # for scripts and cron
```

To keep the passphrase out of your shell history, put it in a file that only you can read
and load it with `export LOGANON_PASSPHRASE="$(cat ~/.loganon_pass)"`.

### macOS

```bash
chmod +x log_anonimizer
xattr -d com.apple.quarantine log_anonimizer       # only if Gatekeeper blocks a downloaded binary
./log_anonimizer                                   # wizard in Terminal / iTerm
./log_anonimizer -a ~/Cases/4711/export.csv
./log_anonimizer -d ~/Cases/4711/export.anon.csv
./log_anonimizer -show ~/Cases/4711/export.anonmap -find HOST_0003
```

Use the `darwin_arm64` build on Apple Silicon (M1 and later) and `darwin_amd64` on Intel Macs.

### Commands and options

```
log_anonimizer                          interactive wizard
log_anonimizer -a <file|folder> [opts]  anonymize
log_anonimizer -d <file|folder> [opts]  de-anonymize with the matching map
log_anonimizer -verify <file|folder>    check anonymized output (add -m to check every known value)
log_anonimizer -show <map>              list every token in the map and its real value
log_anonimizer -show <file|folder>      only the tokens used in that output, with counts
```

| Option | Meaning |
|---|---|
| `-o <path>` | output file or folder (default: next to the input, see below) |
| `-m <map>` | with `-a`: an existing map is **extended**, so values seen in an earlier run keep their tokens. With `-d`: the map to use (default: the one next to the input) |
| `-find <text>` | with `-show`: only tokens or values containing the text (also reveals secrets) |
| `-p <profile>` | profile name or `.yaml` file (default `default`) |
| `-no-encrypt` | write the map as plain JSON (not recommended) |
| `-f` | overwrite existing output and map |
| `-q` | no progress messages |
| `-profiles` | list saved profiles |
| `-print-profile` | print the effective profile as YAML |
| `-version` | print the version |

| Input | Output of `-a` | Output of `-d` |
|---|---|---|
| `data.csv` | `data.anon.csv` + `data.anonmap` | `data.anon.csv` → `data.restored.csv` |
| folder `logs/` | `logs.anon/` (file and folder names anonymized too) + `logs.anonmap` + `logs.anon/ANONYMIZATION_REPORT.txt` | `logs.anon/` → `logs.restored/` |
| any text with tokens | | `report.md` → `report.restored.md` |

Environment: `LOGANON_PASSPHRASE` holds the map passphrase; `LOGANON_PROFILE_DIR` changes
where named profiles are stored.

Exit codes: `0` ok, `1` error, `2` wrong usage, `3` original values were found in the output.

### See what a token stands for: `-show`

Reading a mix of `HOST_0003` and `USER_0001` gets confusing quickly. `-show` reads the map and prints a table.
Give it the map to list everything, or an anonymized file or folder to list only the tokens used there.
The map next to the file is found automatically; otherwise pass `-m`.

```
$ log_anonimizer -show sample.anon.log
map:     sample.anonmap (not encrypted, 25 values)
used in: sample.anon.log (25 distinct tokens, 45 occurrences)

HOSTNAMES
  HOST_0001    fw-edge01                            2×
  HOST_0003    WS-SOMCHAI01                         3×
  ...
USERS
  USER_0001    somchai.k                            6×
  ...
SECRETS
  SECRET_0001  Wi*********                          1×

Secrets are partly hidden; look one up with -find SECRET_0001.
These are the REAL values: do not paste this output where the anonymized logs go.
```

`-find` narrows the table (`-find somchai`, `-find HOST_0003`). The wizard has the same thing
under "Show what each token stands for". The full listing for the example is in
[`examples/show.txt`](examples/show.txt).

## Example: anonymize, then de-anonymize

Everything in [`examples/`](examples) was produced by the commands below from fictional data.
[`examples/profile.yaml`](examples/profile.yaml) names the organisation (`acme`) as a sensitive term.

```bash
cd examples
log_anonimizer -a sample.log -p profile.yaml     # sample.anon.log + sample.anonmap
log_anonimizer -d sample.anon.log                # sample.restored.log, identical to sample.log
log_anonimizer -d ai_report.md -m sample.anonmap # ai_report.restored.md
log_anonimizer -show sample.anon.log > show.txt  # the token table
```

**[`sample.log`](examples/sample.log)** (excerpt):

```
<134>1 2026-10-10T08:16:00+07:00 FW-ACME-01 - - - - TRAFFIC,deny,10.20.1.15,203.0.113.80,tcp,443,rule=Block-External
2026-10-10 08:17:31 10.20.5.10 POST /Microsoft-Server-ActiveSync/default.eas Cmd=Sync&User=somchai.k%40acme.example&DeviceId=4f2a9c71b3e84d0f&DeviceType=iPhone 443 - 198.51.100.61 Apple-iPhone/1.0 - 200 0 0 31
2026-10-10 08:18:12 10.20.5.10 GET /portal/login.aspx user=jdoe&password=Winter2026!&lang=th 443 - 10.20.8.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+Chrome/120.0.0.0 - 302 0 0 12
<Event>...<Computer>WS-SOMCHAI01.corp.acme.example</Computer>...<Data Name='TargetUserName'>somchai.k</Data><Data Name='TargetDomainName'>ACME</Data><Data Name='TargetUserSid'>S-1-5-21-3623811015-3361044348-30300820-1104</Data>...<Data Name='SubjectUserSid'>S-1-5-18</Data>...
kernel: IPfilter Dropped: IN=eth0 MAC=ff:ff:ff:ff:ff:ff:00:1a:2b:3c:4d:5e:08:00 SRC=10.20.8.44 DST=10.20.8.255 PROTO=UDP
copy C:\Users\somchai.k\Desktop\salary-2026.xlsx to \\FS-ACME02\finance\ by ACME\somchai.k
GET http://203.0.113.9@evil.example/backup/10.20.0.5.7z from 198.51.100.23 (probe for a backup of the DC)
```

**After `-a`: [`sample.anon.log`](examples/sample.anon.log)**

```
<134>1 2026-10-10T08:16:00+07:00 HOST_0002 - - - - TRAFFIC,deny,IP_0001,EXTIP_0003,tcp,443,rule=Block-External
2026-10-10 08:17:31 IP_0002 POST /Microsoft-Server-ActiveSync/default.eas Cmd=Sync&User=USER_0001%40DOMAIN_0001&DeviceId=DEVICE_0001&DeviceType=iPhone 443 - EXTIP_0004 Apple-iPhone/1.0 - 200 0 0 31
2026-10-10 08:18:12 IP_0002 GET /portal/login.aspx user=USER_0002&password=SECRET_0001&lang=th 443 - IP_0003 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+Chrome/120.0.0.0 - 302 0 0 12
<Event>...<Computer>HOST_0003.DOMAIN_0002</Computer>...<Data Name='TargetUserName'>USER_0001</Data><Data Name='TargetDomainName'>DOMAIN_0003</Data><Data Name='TargetUserSid'>S-1-5-21-SID_0001-1104</Data>...<Data Name='SubjectUserSid'>S-1-5-18</Data>...
kernel: IPfilter Dropped: IN=eth0 MAC=ff:ff:ff:ff:ff:ff:MAC_0001:08:00 SRC=IP_0003 DST=IP_0005 PROTO=UDP
copy C:\Users\USER_0001\Desktop\salary-2026.xlsx to \\HOST_0005\finance\ by DOMAIN_0003\USER_0001
GET http://EXTIP_0005@evil.example/backup/IP_0004.7z from EXTIP_0002 (probe for a backup of the DC)
```

Note what is kept: timestamps, ports, the browser version `Chrome/120.0.0.0` (not mistaken
for an IP), the built-in SID `S-1-5-18`, the broadcast MAC, and the attacker domain
`evil.example` (an IOC). `somchai.k` is `USER_0001` everywhere: in the SSH log, the URL-encoded
ActiveSync user, the Windows event, the profile path and `ACME\somchai.k`.

**After `-d`:** `sample.restored.log` is byte-for-byte identical to `sample.log`.

`-d` also works on any text that mentions tokens, for example the findings you get back from
a vendor or an AI that only saw the anonymized log.
[`ai_report.md`](examples/ai_report.md) becomes [`ai_report.restored.md`](examples/ai_report.restored.md):

```
before: 2. USER_0001 logged on from EXTIP_0001 over SSH, then on workstation HOST_0003.DOMAIN_0002
after:  2. somchai.k logged on from 203.0.113.45 over SSH, then on workstation WS-SOMCHAI01.corp.acme.example

before: review mailbox USER_0001@DOMAIN_0001 and device DEVICE_0001. HOST_9999 is mentioned by mistake.
after:  review mailbox somchai.k@acme.example and device 4f2a9c71b3e84d0f. HOST_9999 is mentioned by mistake.
```

Tokens that are not in the map (`HOST_9999`) are left as they are and listed in the summary.

> [`examples/sample.anonmap`](examples/sample.anonmap) is stored **unencrypted** only so you can
> read how a map looks. Keep real maps encrypted and never share them.

## What gets replaced

| Kind | Example | Becomes |
|---|---|---|
| Internal / public IP (v4 and v6) | `10.1.2.3`, `fe80::1`, `203.0.113.5` | `IP_0001`, `EXTIP_0001` |
| Hostname, internal FQDN | `DC01`, `dc01.corp.acme.example`, `www.corp.acme.example` | `HOST_0001`, `HOST_0001.DOMAIN_0001`, `www.DOMAIN_0001` |
| Account, e-mail | `CORP\jdoe`, `jdoe@acme.example`, `jdoe%40acme.example`, `PC01$` | `DOMAIN_0002\USER_0001`, `USER_0001@DOMAIN_0003`, `HOST_0002$` |
| Paths with names | `C:\Users\somchai\`, `/home/bob/`, `\\FS01\share` | `C:\Users\USER_0002\`, `\\HOST_0002\share` |
| Windows SID | `S-1-5-21-1111-2222-3333-500` | `S-1-5-21-SID_0001-500` (the RID is kept) |
| MAC | `00:1a:2b:3c:4d:5e`, `00-1A-…`, `001a.2b3c.4d5e` | `MAC_0001` |
| Secrets | `password=`, `token=`, `Authorization:`, `Cookie:`, IIS `cs(Cookie)` | `SECRET_0001` |
| Device IDs | ActiveSync `DeviceId=`, IMEI | `DEVICE_0001` |
| Sensitive terms | organisation names, project codes (`sensitive_terms`) | `ORG_0001`; words that contain one, such as `ACMEDC01`, become `NAME_0001` |

Values are found from their context: CSV column names, IIS `#Fields`, Windows event
`<Data Name=…>`, `<Computer>`, syslog headers, `key=value` / `key: value` / JSON pairs, URL
parameters, `DOMAIN\user`, e-mail and profile paths. After that, every learned value is also
searched for in free text, so a hostname that appears on its own in a message is replaced too.

**Kept on purpose:** timestamps, event IDs, process names, hashes, ports, status codes, rule
names, `127.0.0.1`, `::1`, `0.0.0.0`, netmasks, RFC 1918 range boundaries in firewall rules,
public resolvers (`8.8.8.8` …), version numbers (`Chrome/120.0.0.0`, `rv:1.8.0.6`,
`Version=4.0.0.0`), well-known SIDs, built-in accounts (`NT AUTHORITY\SYSTEM`,
`Administrator`, `root`), and public domains (`microsoft.com`, `google.com` …).

Attacker input is evidence, so it is kept as well: usernames from failed logins (`invalid user oracle`),
URLs that scanners probe (`GET /home/ubuntu/.config/gcloud`), and crawler contacts in
User-Agents (`+bot@crawler.example`). Addresses inside such strings are still replaced, as in
`http://IP_0004admin/` or `/backup/IP_0004.7z`.

**External domains are kept** because they are usually IOCs (C2 domains, phishing sites). A
domain is replaced only when it is known to be internal: it named a machine of the
organisation (`<Computer>`, a syslog header, a `Hostname (Origin)` column), it is an e-mail
or `DOMAIN\user` domain, it ends in an `internal_suffixes` entry, or it contains a sensitive
term. At the end of each run, the summary lists the most frequent domains left in clear text
so you can spot your own organisation's domain and add it to `sensitive_terms`.

## Supported input

- Any line-based text log: syslog (RFC 3164/5424), Linux auth/audit, firewall, AV and EDR logs, KAPE console logs …
- CSV, using the column names, e.g. LogRhythm exports (`Host (Origin)`, `User (Impacted)`, `Entity (Origin)` …) and EvtxECmd (`Computer`, `UserName`). The original quoting, CRLF line endings and BOM are kept.
- IIS W3C logs (`#Fields:`), Windows event XML, EvtxECmd JSON payloads.
- UTF-8, UTF-8 with BOM, UTF-16 (written back as UTF-8).
- Folders, such as a whole KAPE triage collection, processed with one shared map.

**Binary files are skipped and not copied to the output.** This covers evtx, registry hives,
`$MFT`, `$J`, lnk files and databases. Parse them to CSV first, e.g. with Eric Zimmerman's
tools (EvtxECmd, RECmd, MFTECmd), then anonymize the CSV.

## The map file

The `.anonmap` file turns tokens back into real values. **Never send it with the output.**

- It is encrypted by default: AES-256-GCM, with a key derived by Argon2id (t=3, 64 MiB, 4 lanes) and an authenticated header. A wrong passphrase or a modified file is rejected.
- It is written with `0600` permissions and replaced atomically.
- Reuse it with `-m` for later batches of the same case, so values seen before keep their tokens and new values get new numbers.
- It records which inputs it was used for: path, SHA-256 and time.

If the input already contains text that looks like a token (say, an earlier anonymized
report), a prefix such as `ANON_` is added to all new tokens so `-d` cannot mix them up.

## Profiles

Options that rarely change belong in a profile, not on the command line. The wizard can save
one, or you can write it yourself:

```bash
log_anonimizer -print-profile > customer-a.yaml     # start from the defaults
log_anonimizer -a export.csv -p customer-a.yaml
```

```yaml
name: customer-a
anonymize:            # every kind is on by default
  public_ip: false    # keep public addresses as IOCs
  mac: true
sensitive_terms: [acme, acme.co.th, project-falcon]
internal_suffixes: [local, corp, acme.lan]
secret_keys: [password, token, apikey, x-custom-secret]
allow:
  ips: [192.0.2.0/24]
  domains: [vendor-cdn.example]
  users: [svc-monitoring]
encrypt_map: true
```

Named profiles (`-p customer-a`) live in the user config directory, for example
`%AppData%\log_anonimizer\profiles` on Windows, `~/.config/log_anonimizer/profiles` on Linux
and `~/Library/Application Support/log_anonimizer/profiles` on macOS.

## Limitations

- Detection is heuristic. Read the `verify` line and the "domains kept in clear text" list in the summary, and skim the output before you share it.
- Values that differ only in letter case (`DC01` / `dc01`) share one token so correlation works; `-d` restores the spelling seen first.
- Common words that log parsers put into user or host fields (for example `host`) are replaced in that field only, not searched for in free text.
- Speed: the input is read two or three times to learn values, then written, then verified, on one CPU core. On an Apple M-series Mac, a 51 MB LogRhythm export takes about 11 s and a KAPE triage with 1.5 GB of text logs about 3.5 minutes.

## Development

```bash
go test ./...          # unit, end-to-end, CLI and wizard tests (no real data needed)
go vet ./...
./scripts/build.sh     # release binaries for every platform
```

Layout: `cmd/log_anonimizer` (CLI), `internal/anon` (detectors, engine, restore, verify),
`internal/vault` (map and encryption), `internal/profile`, `internal/tui` (wizard),
`internal/app` (shared by CLI and wizard).

Never commit real logs. `Sample_Logs/` and `Simple_Logs/` are in `.gitignore`.
