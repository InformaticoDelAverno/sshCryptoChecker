# sshCryptoChecker

Audits the cryptography your SSH servers negotiate: key exchange, host keys,
ciphers, MACs and compression. It classifies each server as **secure**,
**acceptable**, **weak** or **insecure**, tells you whether it is
**post-quantum ready**, and generates the `sshd_config` block that fixes
whatever it finds.

The algorithm lists live in an **editable configuration file**, not in the
code: what is secure today may not be tomorrow, and updating the tool should
mean editing a JSON file, not touching Python.

> The tool speaks **English and Spanish**: the wizard, the help text and the
> reports follow `--lang {en,es}` (without it, the system language). The
> machine-oriented formats (json, sarif, csv, openmetrics) keep their keys in
> English on purpose.

---

> **Español:** este manual también está disponible en [español](../es/README.md).

## Contents

- [Features](#features)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [Ways to specify a target](#ways-to-specify-a-target)
- [The interactive wizard (--wizard)](#the-interactive-wizard---wizard)
- [Languages (--lang)](#languages---lang)
- [Report formats](#report-formats)
- [Advanced usage](#advanced-usage)
- [Known vulnerabilities](#known-vulnerabilities)
- [Detection plugins](#detection-plugins)
- [The policy file](#the-policy-file)
- [Standards conformance (NIST, FIPS, ENS, PCI DSS, ISO…)](#standards-conformance-nist-fips-ens-pci-dss-iso)
- [How the grade is computed](#how-the-grade-is-computed)
- [What exactly it checks](#what-exactly-it-checks)
- [Exit codes and CI integration](#exit-codes-and-ci-integration)
- [Web interface](#web-interface)
- [MCP interface](#mcp-interface)
- [Options reference](#options-reference)
- [Cookbook: one example per option](#cookbook-one-example-per-option)
- [Authenticated configuration audit](#authenticated-configuration-audit)
- [Limitations and legal notes](#limitations-and-legal-notes)
- [License](#license)
- [Extension guides included](#extension-guides-included)

---

## Features

- **No dependencies.** Just the Python 3.9+ standard library. It can be copied
  onto a bastion and run directly.
- **Speaks real SSH.** It implements the transport layer (RFC 4253): it reads
  the server's `SSH_MSG_KEXINIT` and, optionally, completes a key exchange to
  obtain the actual host key (type, size and fingerprint).
- **Never authenticates.** It sends no username, no password and no session
  data: it closes the connection as soon as it has the information.
- **Post-quantum.** It detects the hybrid methods (`mlkem768x25519-sha256`,
  `sntrup761x25519-sha512@openssh.com`, …) and distinguishes between *not
  ready*, *ready* and *enforced*.
- **Known vulnerabilities.** Terrapin, Sweet32, Logjam, CBC plaintext
  recovery, SHA-1 signatures, regreSSHion and more. **The detection rules live
  in the JSON**, so adding a new one requires no code changes.
- **Host certificates.** It extracts the serial number, identifier, principals,
  validity window and CA fingerprint; it warns about certificates that have
  expired or are about to.
- **Four output formats:** colored console, plain text, JSON and
  self-contained HTML.
- **Actionable suggestions.** The proposed `sshd_config` is limited to
  algorithms the server already supports, so applying it locks nobody out.
- **Beyond the algorithms.** Accepted authentication methods (by completing a
  real key exchange), SSHFP records in DNS, measured `LoginGraceTime`, and
  detection of host keys shared across servers.
- **Standards conformance.** Effective security strength in bits (NIST
  SP 800-57) and evaluation against twenty-five profiles, each one **verified
  against the published document** and declaring the exact edition: NIST
  SP 800-131A, FIPS 140-3, CNSA 1.0 and 2.0, BSI TR-02102-4, ENS, PCI DSS
  v4.0, CIS, ANSSI and ISO/IEC 27001 A.8.24.

---

## Requirements and installation

Python 3.9 or newer. Nothing else.

### Option 1: run from the repository (no install)

```bash
git clone https://github.com/CHANGEME/sshCryptoChecker.git
cd sshCryptoChecker
./ssh-crypto-checker servidor.example.com
```

Or, equivalently:

```bash
python3 -m ssh_crypto_checker servidor.example.com
```

### Option 2: install

```bash
pip install .
ssh-crypto-checker servidor.example.com
```

In an isolated environment:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

---

## Quick start

With no arguments, the script shows the full help with examples:

```bash
ssh-crypto-checker
```

Don't want to learn the options by heart? The **interactive wizard** asks for
them one by one and, at the end, shows you — and runs — the command it built:

```bash
ssh-crypto-checker --wizard
```

Scan a server:

```bash
ssh-crypto-checker servidor.example.com
ssh-crypto-checker 192.0.2.10:2222
ssh-crypto-checker '[2001:db8::1]:22'
```

Several servers at once:

```bash
ssh-crypto-checker web01.example.com db01.example.com:2222 192.0.2.10
```

From an inventory, generating an HTML report:

```bash
ssh-crypto-checker -f inventario.txt --format html -o auditoria.html
```

Only the summary table (useful with many servers):

```bash
ssh-crypto-checker -f inventario.txt --summary-only
```

With the explanation of each algorithm:

```bash
ssh-crypto-checker servidor.example.com --notes
```

Which standards it is evaluated against — **by default, all of them** (25); with
`--profile` you choose one, a subset or a specific edition:

```bash
ssh-crypto-checker servidor.example.com                       # all of them
ssh-crypto-checker servidor.example.com --profile ens,pci-dss-4   # just those two
ssh-crypto-checker servidor.example.com --profile disa-stig-rhel-9-ssh
```

The identifiers come from `--list-profiles`. The full selection story — subsets,
`nombre@edición`, and the `--require-profile` CI gate — is in the
**"Standards conformance"** section below.

---

## Ways to specify a target

| Form | Example | Port |
|---|---|---|
| DNS name | `servidor.example.com` | 22 (or `-p`) |
| DNS name and port | `servidor.example.com:2222` | 2222 |
| IPv4 | `192.0.2.10` | 22 |
| IPv4 and port | `192.0.2.10:2222` | 2222 |
| IPv6 in brackets | `[2001:db8::1]:22` | 22 |
| IPv6 without brackets | `2001:db8::1` | 22 |
| URL | `ssh://servidor.example.com:2222` | 2222 |
| With a username (ignored) | `admin@servidor.example.com` | 22 |

An IPv6 address without brackets **cannot** take a port: there would be no way
to tell it apart from another group of the address.

---

## The interactive wizard (--wizard)

If you would rather not learn the options, the wizard (`-w` / `--wizard`) asks
them one by one —targets and inventory, port, standards to evaluate, output
formats and file, timeouts and concurrency, host keys and remote checks,
authenticated audit and plugins—, **shows the command** it built and offers to
run it:

```bash
ssh-crypto-checker --wizard
ssh-crypto-checker -w            # shorthand
```

The wizard **does not scan on its own**: it assembles the exact `argv` a normal
invocation would use, prints it as a copyable command and hands it to the CLI. So
what it shows and what it runs are the same by construction, and the printed
command can be **saved and re-run** later without the wizard. It ends in `--lang`,
so that copied to another machine it produces the same report. It needs an
interactive terminal (if input is not a TTY, it exits with a notice).

---

## Languages (--lang)

The tool is **bilingual**: English (default) and Spain Spanish. Everything a
person reads comes out in the chosen language: the **wizard** (`--wizard`), the
**full CLI help** (`--help`: the description, each option's help and the
metavariables) and the **body of the readable reports** (`console`, `text` and
`html`). It is chosen like this:

```bash
ssh-crypto-checker server.example.com --lang es      # Spanish
ssh-crypto-checker server.example.com --lang en      # English (default)
```

Without `--lang`, Spanish is chosen when the system **locale** is Spanish
(`LANG`/`LC_ALL`/`LC_MESSAGES` starts with `es`); otherwise English. `--lang`
always overrides the locale, and accepts forms like `es_ES` or `en-GB` (the prefix
is taken). The **machine-readable formats** (JSON, SARIF, CSV, inventory,
OpenMetrics) keep their keys and values in English whatever the language: they are
a contract for tools, not prose for people. The `argparse` scaffolding words
(`usage:`, `options:` and the syntax errors) also stay in English, because Python
ships no translation for them.

---

## Report formats

`--format` accepts `console` (the default), `txt`, `json`, `html`, `csv`, `sarif`,
`inventory` and `openmetrics`. It can be repeated or comma-separated.

```bash
# to the screen
ssh-crypto-checker servidor.example.com

# to a file: each format appends its extension if the path lacks it
ssh-crypto-checker servidor.example.com --format html -o informe
# -> informe.html   (and 'informe.html' is not doubled into 'informe.html.html')

# several formats: -o is the base name and each one appends its extension
ssh-crypto-checker -f inventario.txt --format json,txt,html -o informes/auditoria
# -> informes/auditoria.json, informes/auditoria.txt, informes/auditoria.html
```

- **`console`** — colored, with automatic terminal detection. It honors
  `NO_COLOR` and `FORCE_COLOR`; force it with `--color always|never`.
- **`txt`** — plain text with no escape sequences, with a document header, the
  summary table and an appendix that explains how to read it. Meant to be
  attached to a ticket or an email.
- **`json`** — a versioned document (`schema_version`) with **everything**
  observed, including the raw algorithm lists, the score breakdown and the
  timings. Meant for dashboards and historical series.
- **`html`** — a single self-contained file: no external fonts, scripts or
  stylesheets, so opening it leaks nothing to the network. It adapts to the
  reader's light/dark theme and prints well.
- **`csv`** — one row per finding, with the server columns repeated on each
  one. It is what you need to filter an entire fleet by severity in a
  spreadsheet, or to import the pending work into an issue tracker. A server
  with no findings still produces its row, so a healthy server can be told
  apart from one that was not scanned.
- **`sarif`** — SARIF 2.1.0, the format ingested by GitHub code scanning, Azure
  DevOps and several dashboards. Each server is an *artifact* with URI
  `ssh://host:puerto`, each finding a *result*, and the finding identifier is
  the rule. The fingerprints (`partialFingerprints`) are stable across runs,
  so the dashboard can tell a finding that reappears from a new one.
- **`inventory`** — the cryptographic inventory in Markdown, in the format
  **PCI DSS v4.0 requirement 12.3.3** asks for: in-scope systems, each
  algorithm listed once with the servers that offer it, the ones to retire, the
  position on post-quantum cryptography and the response strategy. See
  [Conformance](#standards-conformance-nist-fips-ens-pci-dss-iso).

- **`openmetrics`** — the Prometheus exposition format, for writing straight
  into node_exporter's *textfile collector* directory. A report answers a
  question somebody asked; metrics answer the ones nobody is awake to ask: a
  server whose grade dropped in the small hours, a fleet whose post-quantum
  coverage stopped climbing, a scan that silently stopped running. The grade is
  exported as an **ordinal** (0 is A+) and not as a label, because "the grade
  got worse" is the alert you actually want and labels cannot express it:
  `ssh_target_grade > 2`.

The extensions used when writing several formats are `.console.txt`, `.txt`,
`.json`, `.html`, `.csv`, `.sarif.json`, `.inventory.md` and `.prom`.

When writing to a file, color codes are never emitted, even if
`--color always` is requested.

---

## Advanced usage

Beyond the basic scan, the tool compares against an earlier scan (`--compare`),
audits this machine's `ssh` client (`--audit-client`), scans through a bastion,
reads targets and credentials from an **inventory file** (`-f`, with `user=`,
`auth=`, `key=`, `password-env=`) and runs additional remote checks (SSHFP in DNS
with `--sshfp`, local `known_hosts` with `--known-hosts`, login grace…). Each has
its example in the [Cookbook](#cookbook-one-example-per-option); the how and why
of each, in full, is in [`docs/uso-avanzado.md`](uso-avanzado.md).

---

## Known vulnerabilities

Beyond classifying algorithms, the tool checks **65 concrete vulnerabilities** in
OpenSSH, Dropbear and libssh (49 server-side, 14 for the client on that same
machine). The design point: **detection lives in the JSON, not in the code** —
adding one is editing a list, no Python touched.

```bash
ssh-crypto-checker --list-vulnerabilities
```

They are detected by three paths: **on the wire** (10, what the server actually
offers, no margin of error), **by version** (54, inferred from the banner, always
with the warning that distros backport patches without changing the number) and
**configuration-conditioned** (4, which require `--audit-config`). The rule
governing this section: **not looking is not the same as looking and finding
nothing** — a check that needs data the scan did not collect comes out *not
determined*, with the option that would resolve it, never as "unaffected".

Vulnerabilities get **their own report section**, separate from configuration
findings, because they answer a different question: a finding says the server is
configured in a way the policy disapproves of; a vulnerability, that someone
published an attack against the software it runs. The fleet summary orders them by
how many machines share each problem (`by_vulnerability`), which is where to start.

How to write a new detection, the condition grammar, the analysis of
pre-authentication compression (`zlib` vs `zlib@openssh.com`, CVE-2026-23943, STIG
V-258002) and the verification against the primary sources are in
[`docs/politica-vulnerabilidades.md`](politica-vulnerabilidades.md).

---

## Detection plugins

A policy-file rule *matches*: a name, a version window, a directive's value. What
it cannot do is **compute** — divide a number, subtract two dates, factor a
modulus. That is what plugins are for: **a `.py` file** dropped into a plugin
directory and it runs. **Almost every check the tool makes is a plugin** (twelve
built in, in
[`builtin/`](../../ssh_crypto_checker/plugins/builtin/README.md)); it is not a
third-party system with the important things hidden elsewhere. Two guarantees, and
they are pinned by tests:

- **A plugin cannot change the grade.** It receives a `ServerView` of the
  *observed* — banner, algorithms, keys, configuration — never the score, grade or
  verdict, and its result is added to the report *after* the grade is computed. So
  an absent, broken or third-party plugin cannot silently move the rating, which is
  the one thing an auditor has to be able to stand behind.
- **A plugin cannot take down the scan.** Whatever it throws is caught and
  reported as a finding that names it; the scan goes on.

Loading code is loading code, so plugin directories are **explicit** (never the
working directory) and one writable by group or others is rejected, with the exact
`chmod` — the same rule sshd applies with `StrictModes`. There are three kinds
(`KIND`): `vulnerability` and `check` run per server, `fleet` once at the end (for
what is not a property of a single server, like a shared host key).

```bash
ssh-crypto-checker --list-plugins                 # what would load, and from where
ssh-crypto-checker server --plugin-dir ./my-plugins
```

The full contract — metadata, `NEEDS`, what `check` may return, how to test it and
why the scoring model is **not** a plugin — is in
[`docs/plugins.md`](plugins.md), with a guide per kind
([check](plugin-check.md), [fleet](plugin-fleet.md),
[vulnerability](plugin-vulnerability.md)).

---

## The policy file

It is the heart of the tool and **the only place where whether an algorithm is
secure gets decided**: the classification, the categories and their scores, the
key-size requirements, the version advisories, and the tags that Terrapin,
*encrypt-then-MAC* and the compression state depend on. It ships as
[`ssh_crypto_checker/data/algorithms.json`](../../ssh_crypto_checker/data/README.md).

```bash
ssh-crypto-checker --export-policy mi-politica.json   # take an editable copy
ssh-crypto-checker --show-policy --config mi-politica.json   # see what it holds and which loaded
ssh-crypto-checker --config mi-politica.json server.example.com   # use it
```

Without `--config`, the first that exists is used: `$SSH_CRYPTO_CHECKER_CONFIG`,
`./ssh-crypto-checker.json`, `~/.config/ssh-crypto-checker/algorithms.json`,
`/etc/ssh-crypto-checker/algorithms.json`, and finally the packaged copy. `.toml`
(Python 3.11+) and `.yaml` (with PyYAML) are also accepted; the reference format
is JSON. The file is validated on load: a nonexistent category, a missing class or
malformed JSON gives an error with the line and column, not a silent failure.

The manuals for writing your own policy, with the full structure, start at
[`docs/politicas.md`](politicas.md) and continue by topic:
[algorithms and tags](politica-algoritmos.md),
[scoring](politica-puntuacion.md),
[configuration](politica-configuracion.md),
[vulnerabilities](politica-vulnerabilidades.md) and
[standards](politica-normativas.md).

---

## Standards conformance (NIST, FIPS, ENS, PCI DSS, ISO…)

Beyond its own grade, each server is evaluated against **published standards**,
independently. A standard is not code of this tool: it is a document maintained
by other people and revised on their own schedule, so each one lives in **its own
directory**, **one file per edition**, and is **evaluated**, not compiled:
[`ssh_crypto_checker/data/profiles/`](../../ssh_crypto_checker/data/profiles/README.md).
When the scan does not see enough to judge, the result is **not assessed**, never
*compliant*: a check that could not run has not been passed, it was skipped.

Two different questions are answered. *How strong is it?* — a level in bits
(High ≥192 · Moderate ≥128 · Legacy ≥112 · Inadequate <112, per NIST SP 800-57),
that of the weakest algorithm the server accepts. And *does it meet standard X?*
— a profile that passes, fails or comes out not assessed. The reasoning behind
each level and each profile is in
[`docs/politica-normativas.md`](politica-normativas.md).

They are selected with `--profile <id>` (the edition **in force**) or `--profile
<id>@<edition>` to pin one (repeatable, or comma-separated), and listed with
`--list-profiles`. `--require-profile <id>` is also a **CI gate**: it exits with
code 1 if any server does not comply. The **25 built-in** profiles:

| `--profile` | Authority | What it requires |
|---|---|---|
| `nist-sp-800-131a` | NIST | ≥112 bits, no SHA-1 signatures, no 3DES |
| `fips-140-3` | NIST | FIPS-approved functions only (Annex C + FIPS 186-5 + SP 800-56A r3) |
| `cnsa-1.0` | NSA | P-384/SHA-384 and AES-256-GCM; no stock sshd conforms |
| `cnsa-2.0` | NSA | ML-KEM-1024 and ML-DSA-87 only, no classical fallback |
| `bsi-tr-02102-4` | BSI (Germany) | 120 bits; only the identifiers in tables 2-5 |
| `ens` | CCN (Spain) | 128 bits; only what CCN-STIC-807 tables 4-4 to 4-7 list |
| `pci-dss-4` | PCI SSC | *Strong cryptography*: ≥112 bits, RSA ≥2048 |
| `cis-benchmark-ssh` | CIS | Blacklist of weak algorithms |
| `disa-stig-*-ssh` (15) | DISA (USA) | Per-platform FIPS whitelist — see `--list-profiles` |
| `anssi-rgs` | ANSSI (France) | Rules by mechanism; RSA ≥2048 through 2030 |
| `iso-27001-a-8-24` | ISO/IEC | Conformance with your own policy |

**Each rule points to an exact section or table of a real document**, cited in
the profile's `reference` and `notes` fields and, verbatim, in
`docs/estandares/CITATION_MAP.md`. The source
documents are cited (URL, date and SHA-256) in
`docs/estandares/`; not all may be redistributed
(PCI DSS and ISO/IEC are paywalled; NIST is public domain; CIS is CC BY-NC-SA),
so they are **cited** and obtained from their publisher, not bundled.

A `PASS` is triage, not a certificate: several standards require things no scan
can see (the ENS asks for CPSTIC products; FIPS 140-3, a validated module). For
requirement **PCI DSS 12.3.3** — the documented cryptographic inventory — there
is `--format inventory`. All of it, along with the verification against the
primary sources and how to write your own profile, is in
[`docs/politica-normativas.md`](politica-normativas.md).

```bash
# Evaluate against two profiles and block CI if they fail
ssh-crypto-checker -f inventario.txt --profile ens,pci-dss-4 --require-profile ens

# See the available profiles and their edition
ssh-crypto-checker --list-profiles
```

---

## How the grade is computed

**Each class scores by its weakest algorithm** -- not an average: a server is only
as strong as the worst cipher it is willing to negotiate. The classes combine with
their weights, a few modifiers add or subtract (non-strict KEX, no post-quantum, a
short host key, a small DH group), and the number becomes a letter. Then the
**caps** come down: any insecure algorithm forces `F`, a weak one caps at `C`, a
host key below the minimum at `D`, a confirmed high or critical vulnerability at
`C`, and a **measured** critical one -- not inferred from the announced version --
at `F`. The JSON carries a `score_breakdown` that makes every grade auditable.

The **verdict** (`secure`/`acceptable`/`weak`/`insecure`) is computed apart from
the grade, with a single rule tying them together: **no `weak` server may grade
better than `C`, and no `insecure` one better than `F`**.

> The whole system -- the five steps, the seven cap conditions, the verdict table
> and a worked example calculated step by step -- is in
> [`docs/en/como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md).
## What exactly it checks

**On the wire, without authenticating:**

- Identification string and software version (and any preceding banner lines).
- The 10 algorithm sets of the `SSH_MSG_KEXINIT`, with the client→server and
  server→client directions taken separately (a warning is raised if they
  differ).
- Strict key exchange support (`kex-strict-s-v00@openssh.com`).
- Actual Terrapin exploitability: `chacha20-poly1305@openssh.com`, or a CBC
  cipher together with a `*-etm@openssh.com` MAC, without strict KEX.
- Presence of post-quantum hybrid methods.

**By completing a key exchange** (can be skipped with `--no-host-keys`):

- Type, size in bits and SHA-256 fingerprint of every host key, in the same
  format as `ssh-keygen -lf`.
- OpenSSH host certificates: serial, identifier, principals, validity window,
  and the CA's type and fingerprint.
- The size of the Diffie-Hellman group the server actually picks.

For that it implements X25519, ECDH over P-256/384/521 and Diffie-Hellman over
MODP groups 1 and 14, plus `diffie-hellman-group-exchange-*` (where it is the
server itself that sends the modulus). One connection is opened per host key
family.

**Known vulnerabilities:** 63 checks covering OpenSSH, Dropbear and libssh.
Nine are observed on the wire (Terrapin, CBC, Sweet32, Logjam, RC4, SHA-1
signatures, SSH-1 support, `none` cipher, `none` MAC) and the rest are
inferred from the banner. The version-inferred ones are always flagged as
advisory, because distributions apply patches without changing the number.
**They do not affect the score** unless `version_advisories_affect_score` is
set to `true`. See
[Known vulnerabilities](#known-vulnerabilities).

**With `--auth-methods` or `--audit-config`:** four rules only apply if a
non-default option is active (for example `GSSAPIAuthentication yes`). Without
that data **they are not assumed to be ruled out**: they are reported as *not
determined*, stating which option would resolve them.

---

## Exit codes and CI integration

| Code | Meaning |
|---|---|
| `0` | Everything scanned and nothing exceeds the `--fail-on` threshold |
| `1` | There are findings of severity equal to or worse than `--fail-on` |
| `2` | Usage error, or the policy file could not be loaded |
| `3` | Some server could not be scanned |

`--fail-on` accepts `never` (the default), `critical`, `high`, `medium`, `low`
and `info`.

```yaml
# .gitlab-ci.yml
auditoria-ssh:
  image: python:3.12-slim
  script:
    - pip install .
    - ssh-crypto-checker -f inventario.txt --format json,html -o informe
                         --fail-on high --quiet
  artifacts:
    when: always
    paths: [informe.json, informe.html]
```

To also treat unreachable servers as a failure, check the exit code with
`[ $? -eq 0 ]` instead of `-le 3`.

---

## Web interface

An **additional** way to use the tool, not a replacement: the same scan, the
same policy and the same reports, from a form. Zero dependencies here too (the
server is the standard library's `http.server`). The scan's report downloads
in **any of the eight formats**, in the chosen language — one scan, every
format.

```bash
# Locally (listens on 127.0.0.1 by default)
python3 -m ssh_crypto_checker.web
# → http://127.0.0.1:8417/

# In a container, in one shot (uses docker-compose.yml)
make web-up      # builds and starts in the background → http://localhost:8417/
make web-logs    # follow the log
make web-down    # stop and clean up
```

**Open by default (no token, no users, no sign-up).** The convenient shape for
an internal deployment: anyone who reaches the port uses it, on any interface.
The token is the **one switch** that closes it — set it and every `/api` request
must carry `X-Auth-Token` (constant-time compare):

```bash
# Open, on your internal LAN (what `make web-up` does with nothing else)
docker compose up -d --build
# equivalent to:  python3 -m ssh_crypto_checker.web --host 0.0.0.0

# Closed, with a token
SSH_CRYPTO_CHECKER_WEB_TOKEN=a-secret make web-up
# or by hand, without compose:
docker run --rm -p 8417:8417 -e SSH_CRYPTO_CHECKER_WEB_TOKEN=un-token sshcryptochecker-web
```

It scans whatever the container can reach: published without a token it is an
SSRF machine. Keep it on an internal network or behind your TLS proxy; to expose
it, alongside the token set `SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1` and start it
with no route to your private ranges (see "Web security" below).

What the CLI treats as deployment options arrives through variables and
volumes, not through the form (so no secret ever travels through the browser):

```bash
# Your own policy (the same variable the CLI honours)
docker run --rm -p 8417:8417 \
  -v $PWD/mi-politica.json:/config/algorithms.json:ro \
  -e SSH_CRYPTO_CHECKER_CONFIG=/config/algorithms.json \
  sshcryptochecker-web

# Detection plugins (equivalent to --plugin-dir)
docker run --rm -p 8417:8417 \
  -v $PWD/mis-plugins:/plugins:ro \
  -e SSH_CRYPTO_CHECKER_PLUGIN_DIR=/plugins \
  sshcryptochecker-web
```

The form covers what makes sense on the web: targets and a pasted inventory
(labels and per-host options work as in the file), standards to evaluate and
require, IP family, timeouts and concurrency, the unauthenticated remote
checks (`--auth-methods`, `--sshfp` with its DNS servers, `--login-grace`,
`--max-startups`) and the presentation. Deliberately CLI-only:
`--audit-config` (it needs credentials, which have no business in a form),
`known_hosts`, history and comparison (they live in the operator's files) and
`--audit-client` (it would audit the container, not your machine).

### Web security

The web layer is hardened against the known classes of attack, with tests that
hold it (`tests/test_web.py`):

- **No resource exhaustion.** Every dimension an anonymous caller could inflate
  has a ceiling: body size (2 MB), target count, concurrency, timeout, retries,
  `login-grace`, `max-startups` and simultaneous scans (past which, `503`). A
  giant `Content-Length` is refused with `413` **without being read**.
- **Defensive headers** on every response: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, a strict `Content-Security-Policy` and
  `Referrer-Policy: no-referrer`. Reports download as attachments, never
  rendered in the origin.
- **The token is compared in constant time** (no timing leak), and the HTML
  report **escapes** everything the scanned server controls — a hostile banner
  cannot inject script.

Two things are fixed not in the code but at the **deployment boundary**:

1. **Scanning arbitrary hosts is the tool's function.** On a trusted internal
  network the open mode (above) is convenient and legitimate. Exposed to the
  internet it is another matter — an SSRF machine: there, close it with
  `SSH_CRYPTO_CHECKER_WEB_TOKEN`, turn on
  `SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1` (refuses targets that resolve to
  private/loopback/reserved addresses — defence in depth) and, for the hard
  guarantee, place it with **no network route** to your internal ranges (an
  egress firewall is the only sure thing; the app-level filter only
  approximates it, because of DNS rebinding).
2. **`http.server` is the standard library's basic server, not a hardened
  edge.** For the internet, put it **behind a reverse proxy** that terminates
  TLS, rate-limits and rejects malformed requests.

> In one line: treat it as an **internal** tool unless you have set a
> token/filter **and** put a TLS proxy in front.

---

## MCP interface

A **third** way to use the tool, beside the command line and the web, for a
**language model** to drive it: an **MCP** (Model Context Protocol) server. The
same scan and the same reports as the other two, spoken over **JSON-RPC 2.0 on
stdio** — one JSON message per line, the MCP stdio transport. Zero dependencies
here too: the standard library only, **no SDK, no framework**.

### Requirements

**Python 3.9 or newer. Nothing else** — like the CLI. The MCP server needs no
network to start, no credentials, and no configuration file of its own: it
launches, speaks JSON-RPC over its standard input/output, and inherits the
environment of the client that starts it (so it can be copied to a jump host and
registered there, just like the CLI).

### Installation

Two paths, depending on whether you install the package or run it from the
repository.

**a) Installed (recommended for configuring a client).** `pip install .` leaves
**two** commands on the `PATH`: the CLI and the MCP server. With the command on
the `PATH`, the client configuration is just its name.

```bash
pip install .            # inside the repository (or `pipx install .`)
ssh-crypto-checker-mcp --version     # check it installed
```

> Tip: `pipx install .` installs it isolated in its own environment and leaves
> the commands on the global `PATH`, which is exactly what an MCP client needs to
> find them without activating any virtualenv.

**b) From the repository, without installing.** Equivalent to the above but by
running the module; you must tell Python where the package is (with `-m` from the
repository root, or with `PYTHONPATH`):

```bash
cd /path/to/sshCryptoChecker
python3 -m ssh_crypto_checker.mcp --version
```

### Configuring it in an MCP client

The server is **not run by hand** in a terminal — it speaks JSON-RPC, not to a
person: you **register its command** in an MCP client, which starts it for you
and speaks the protocol. The canonical form, common to almost every client, is an
entry under `mcpServers`:

```json
{
  "mcpServers": {
    "ssh-crypto-checker": {
      "command": "ssh-crypto-checker-mcp"
    }
  }
}
```

**Claude Desktop.** Edit `claude_desktop_config.json` (Settings → Developer →
Edit Config), add the entry above, and **restart** the app. Its location:

| System | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**Claude Code.** Register it with a command (choose the scope with `-s`
`local`/`user`/`project`), or drop a `.mcp.json` in the project root with the same
`mcpServers` block:

```bash
claude mcp add ssh-crypto-checker -- ssh-crypto-checker-mcp
claude mcp list                     # check it appears and connects
```

**Other clients** (Cursor, VS Code, Zed…). They all consume the same
`command`/`args`/`env` shape; only where the file lives changes (e.g.
`.cursor/mcp.json` in Cursor). See the client's documentation for the exact path.

**Without installing (using the repository).** If you would rather not install
the package, point the client at `python3 -m` and tell it which directory to run
in:

```json
{
  "mcpServers": {
    "ssh-crypto-checker": {
      "command": "python3",
      "args": ["-m", "ssh_crypto_checker.mcp"],
      "cwd": "/path/to/sshCryptoChecker"
    }
  }
}
```

> If your client does not support `cwd`, use `"env": { "PYTHONPATH": "/path/to/sshCryptoChecker" }`
> instead. With the package **installed** none of this is needed: the command
> name is enough.

### Checking it works

Before configuring the client you can verify the server by hand: feed it one or
two JSON-RPC messages on standard input and it answers on standard output.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ssh-crypto-checker-mcp
```

It must print two JSON lines: the first with `serverInfo` (`ssh-crypto-checker-mcp`
and the version), the second with the tool list. If instead you see an import
error, the package is not on the `PATH`/`PYTHONPATH` (check the installation).
Once in the client, `scan` with `args: ["server.example.com"]` launches a real
scan.

### Why it loses no option

Parity with the CLI is **by construction, not by upkeep**: every tool call ends
by running the very same `ssh_crypto_checker.cli.main` the terminal runs, with
its output captured. The `scan` tool takes the CLI's own `argv`, so **everything
the command does, the MCP does** — there is no parallel schema for anyone to keep
in sync.

### The tools it exposes

| Tool | What it does |
|---|---|
| `scan` | Scan. `args` is the CLI's argument vector: `["server.example.com", "--format", "json"]`. Every command option works. |
| `help` | The full CLI help (every option), in the chosen language (`lang`). |
| `list_profiles` | List the available conformance profiles. |
| `list_plugins` | List the detection plugins that would load. |
| `list_vulnerabilities` | List the known vulnerabilities the policy checks for. |
| `show_policy` | Show the active scoring policy: classes, weights, grade ladder, source. |

It implements the MCP methods `initialize`, `tools/list`, `tools/call` and
`ping`. **Exit codes are information, not failures**: a scan of a weak server
exits non-zero on purpose, so a completed run is never reported as a tool error —
the code is appended to the text. `isError` is reserved for a call that could not
be made (bad arguments) or an unexpected exception, which is caught so **one tool
can never take the server down**.

> ⚠️ An MCP gives a language model the ability to **launch scans** — and, with
> `scan` and the `--auth-methods`/`--max-startups`/`--login-grace` probes in
> `args`, more intrusive traffic. The same legal limits as the CLI apply (see
> [Limitations and legal notes](#limitations-and-legal-notes)): scan only what
> you are authorised to test. The MCP server opens **no** port and does not listen
> on the network (unlike the web interface): it speaks only over stdio with the
> client that starts it, so the `SSH_CRYPTO_CHECKER_WEB_*` variables do **not**
> apply to it.

---

## Options reference

```
Interactive mode
  -w, --wizard              build the command by answering questions
                            (targets, standards, formats…) and run it

Language
  --lang {en,es}            language of the wizard, the help and the reports
                            (default: English, or the locale's if it is Spanish)

Targets and credentials
  TARGET...                 host, host:port, IP, IP:port or [IPv6]:port
  -f, --file FILE           list of targets ('-' for stdin); repeatable
  --user NAME               default account
  --auth {none,key,password,any}   default authentication mode
  -i, --identity FILE       default private key
  --password-file FILE      read the password from a file
  --password-env VAR        read it from an environment variable
  -p, --port PORT           default port (22)

Additional remote checks
  --auth-methods            enumerate authentication methods (leaves a trace in the log)
  --sshfp                   compare the keys against SSHFP records in DNS
  --dns-server ADDR         name server for SSHFP (accepts addr:port)
  --login-grace [SECONDS]   measure LoginGraceTime
  --known-hosts [FILE]      compare against the local record
  --max-startups [N]        probe the pre-authentication slots
  --audit-config            log in and audit the configuration with 'sshd -T'
  --audit-client            audit this machine's ssh_config with 'ssh -G'
  --all-checks              every non-intrusive one

Scanning
  -t, --timeout SECONDS     per-connection timeout (5.0)
  -c, --concurrency N       targets in parallel (8)
  -r, --retries N           retries per target (1)
  --no-host-keys            skip host key retrieval (faster)
  --no-cert-probes          skip certificate algorithms
  -4 / -6                   force IPv4 or IPv6
  --source-ip ADDR          local source address

Policy and plugins
  --config FILE             policy file to use
  --plugin-dir DIR          load detection plugins from that directory (repeatable)
  --list-plugins            list the plugins that would be loaded and exit
  --export-policy FILE      write an editable copy of the policy and exit
  --show-policy             print a summary of the loaded policy and exit
  --list-vulnerabilities    list the vulnerabilities checked for and exit
  --list-profiles           list the conformance profiles and exit

Output
  --format FMT              console, json, txt, html, csv, sarif, inventory,
                            openmetrics (repeatable or comma-separated)
  -o, --output PATH         output file; appends the format's extension unless
                            the path already ends with it (base name with several formats)
  --color {auto,always,never} / --no-color
  -s, --summary-only        only the summary table
  --notes                   include the explanation of every algorithm
  --no-config-suggestions   omit the generated sshd_config
  -q, --quiet / -v, --verbose

Comparison and history
  --compare FILE            compare against an earlier JSON report (or a history file)
  --fail-on-regression      exit with code 1 if any server got worse
  --history FILE            append this scan to a history file (one line per scan)
  --history-report          print how the estate has moved across the recorded scans

Standards conformance
  --profile ID              evaluate only these profiles instead of all of them
                            (repeatable or comma-separated; ID or ID@edition)
  --require-profile ID      exit with code 1 if any target does not conform to
                            that profile (repeatable or comma-separated)

Behaviour
  --fail-on {never,critical,high,medium,low,info}
```

---

## Cookbook: one example per option

Everything that follows can be copied verbatim. It is ordered by what you want
to achieve, not by the order of `--help`.

### The easiest way: the wizard

If you don't want to learn the options, the wizard asks for them one by one
— targets, **credentials and key** (`-i`, authentication mode, password),
standards to **evaluate** and to **require** (the latter only from among those
evaluated), formats, remote checks, presentation, scanning, **connection**
(bastion, source IP, IPv4/IPv6), policy and plugins, and history/comparison —
then **shows the command** it has built and offers to run it. That command is
copyable: save it and run it again later without the wizard.

```bash
# Interactive mode                                 # --wizard
ssh-crypto-checker --wizard
ssh-crypto-checker -w                              # -w, short for --wizard

# In Spanish (the wizard, the help and the reports)    # --lang
ssh-crypto-checker --wizard --lang es
ssh-crypto-checker servidor.example.com --lang en      # force English
```

The wizard, the help (`--help`) and every report come out in the language you
ask for with `--lang {en,es}`. The default is English; if your locale is
Spanish (`LANG`/`LC_ALL` starts with `es`), it switches to Spanish without you
saying anything. `--lang` always wins over the locale. The command the wizard
builds ends in `--lang`, so that copied to another machine it produces the
same report. The machine-readable formats (json, sarif, csv, openmetrics) keep
their keys and values in English whatever the language: they are a contract
for tools, not prose for people. The scaffolding words of `argparse`
(`usage:`, `options:` and its syntax error messages) also stay in English:
Python ships no translation for them, and patching the library to supply one
was deliberately ruled out.

### Choosing what to scan

```bash
# One server on port 22
ssh-crypto-checker servidor.example.com

# An explicit port, three equivalent ways
ssh-crypto-checker servidor.example.com:2222
ssh-crypto-checker servidor.example.com -p 2222          # -p, --port
ssh-crypto-checker servidor.example.com --port 2222
ssh-crypto-checker 192.0.2.10:2222

# IPv6: bracketed when it carries a port
ssh-crypto-checker '[2001:db8::1]:22'

# Several at once
ssh-crypto-checker web01 web02 db01.example.com:2222

# From an inventory file                   # -f, --file
ssh-crypto-checker -f inventario.txt
ssh-crypto-checker --file inventario.txt

# From another command's output
grep -h '^Host ' ~/.ssh/config | awk '{print $2}' | ssh-crypto-checker -f -

# Several inventories
ssh-crypto-checker -f produccion.txt -f preproduccion.txt
```

### Credentials (only needed for `--audit-config`)

```bash
# Default account for every target                # --user
ssh-crypto-checker -f inventario.txt --audit-config --user auditor

# With a key                                      # --auth, -i/--identity
ssh-crypto-checker servidor --audit-config --auth key -i ~/.ssh/auditor
ssh-crypto-checker servidor --audit-config --auth key --identity ~/.ssh/auditor

# With a password from an environment variable    # --password-env
export AUDIT_PW='...'
ssh-crypto-checker servidor --audit-config --auth password --password-env AUDIT_PW

# With a password from a file                     # --password-file
ssh-crypto-checker servidor --audit-config --auth password --password-file ~/.audit-pw

# Explicitly anonymous: do not authenticate       # --auth none
ssh-crypto-checker servidor --auth none --auth-methods
```

> A literal password is never accepted on the command line or in the
> inventory: it would end up in the shell history and in `ps`.

### Tuning the scan

```bash
# More patience for slow links                    # -t, --timeout
ssh-crypto-checker -f inventario.txt -t 15
ssh-crypto-checker -f inventario.txt --timeout 15

# More targets in parallel (default 8)            # -c, --concurrency
ssh-crypto-checker -f inventario.txt -c 32
ssh-crypto-checker -f inventario.txt --concurrency 32

# Retry the ones that fail                        # -r, --retries
ssh-crypto-checker -f inventario.txt -r 3
ssh-crypto-checker -f inventario.txt --retries 3

# Faster: skip host key retrieval                 # --no-host-keys
ssh-crypto-checker -f inventario.txt --no-host-keys

# Do not probe certificate algorithms             # --no-cert-probes
ssh-crypto-checker -f inventario.txt --no-cert-probes

# Force an address family                         # -4/--ipv4, -6/--ipv6
ssh-crypto-checker servidor.example.com -4
ssh-crypto-checker servidor.example.com --ipv4
ssh-crypto-checker servidor.example.com -6
ssh-crypto-checker servidor.example.com --ipv6

# Leave through a specific interface              # --source-ip
ssh-crypto-checker -f inventario.txt --source-ip 10.0.0.5
```

### Segmented networks

```bash
# Through a bastion already described in ~/.ssh/config  # -J, --jump-host
ssh-crypto-checker -f interna.txt -J bastion
ssh-crypto-checker -f interna.txt --jump-host bastion

# Full bastion spec on the command line
ssh-crypto-checker servidor.interno -J ops@bastion.example.com:2222

# A bastion that needs a specific key                   # --jump-option
ssh-crypto-checker servidor.interno -J bastion \
    --jump-option=-oIdentityFile=~/.ssh/bastion
```

### Additional checks

```bash
# Accepted authentication methods                 # --auth-methods
ssh-crypto-checker servidor --auth-methods

# SSHFP records in DNS                            # --sshfp
ssh-crypto-checker servidor.example.com --sshfp

# ...against a specific name server               # --dns-server
ssh-crypto-checker servidor.example.com --sshfp --dns-server 10.0.0.53
ssh-crypto-checker servidor.example.com --sshfp --dns-server '[::1]:5353'

# Compare against the local known_hosts           # --known-hosts
ssh-crypto-checker -f inventario.txt --known-hosts
ssh-crypto-checker -f inventario.txt --known-hosts /etc/ssh/ssh_known_hosts

# Measure LoginGraceTime (waits up to 130 s)      # --login-grace
ssh-crypto-checker servidor --login-grace
ssh-crypto-checker servidor --login-grace 60      # wait only 60 s

# Probe MaxStartups (intrusive: occupies slots)   # --max-startups
ssh-crypto-checker servidor --max-startups
ssh-crypto-checker servidor --max-startups 40     # hasta 40 conexiones

# Audit the configuration by logging in over SSH  # --audit-config
ssh-crypto-checker servidor --audit-config --user auditor -i ~/.ssh/auditor

# Audit this machine's ssh_config                 # --audit-client
ssh-crypto-checker servidor --audit-client

# Audit an ssh_config before deploying it         # --client-config
ssh-crypto-checker servidor --client-config ./ssh_config.nuevo

# Everything non-intrusive in one go              # --all-checks
ssh-crypto-checker -f inventario.txt --all-checks
```

> `--all-checks` includes `--auth-methods`, `--sshfp`, `--known-hosts`,
> `--audit-client` and `--login-grace`. It does **not** include
> `--max-startups`, which occupies the server's pre-authentication slots, nor
> `--audit-config`, which needs credentials.

### Output formats

```bash
# To the screen (the default)
ssh-crypto-checker servidor

# One format: the extension is added if missing       # --format, -o/--output
ssh-crypto-checker servidor --format html -o informe        # -> informe.html
ssh-crypto-checker servidor --format json --output informe.json  # ya la tiene

# Several: -o is the base name and each one appends its extension
ssh-crypto-checker -f inventario.txt --format json,html,csv -o informes/agosto
# -> informes/agosto.json, .html, .csv

# For node_exporter's textfile collector
ssh-crypto-checker -f inventario.txt --format openmetrics \
    -o /var/lib/node_exporter/ssh.prom

# Cryptographic inventory evidence (PCI DSS 12.3.3)
ssh-crypto-checker -f inventario.txt --format inventory -o inventario-cripto.md

# For GitHub code scanning
ssh-crypto-checker -f inventario.txt --format sarif -o ssh.sarif.json

# Only the summary table                          # -s, --summary-only
ssh-crypto-checker -f inventario.txt -s
ssh-crypto-checker -f inventario.txt --summary-only

# With the explanation of every algorithm         # --notes
ssh-crypto-checker servidor --notes

# Without the suggested sshd_config               # --no-config-suggestions
ssh-crypto-checker servidor --no-config-suggestions

# Color                                           # --color, --no-color
ssh-crypto-checker servidor --color always | less -R
ssh-crypto-checker servidor --no-color

# Less noise / more noise                         # -q/--quiet, -v/--verbose
ssh-crypto-checker -f inventario.txt -q
ssh-crypto-checker -f inventario.txt --quiet
ssh-crypto-checker servidor -v
ssh-crypto-checker servidor --verbose
```

### Policy and plugins

```bash
# Use another policy                              # --config
ssh-crypto-checker -f inventario.txt --config politica-corporativa.json

# Get an editable copy of the one in use          # --export-policy
ssh-crypto-checker --export-policy mi-politica.json

# See which policy is loaded                      # --show-policy
ssh-crypto-checker --show-policy

# Version of the tool                              # --version
ssh-crypto-checker --version

# List what is checked                            # --list-*
ssh-crypto-checker --list-vulnerabilities
ssh-crypto-checker --list-profiles
ssh-crypto-checker --list-plugins

# Load your own plugins                           # --plugin-dir
ssh-crypto-checker servidor --plugin-dir ./mis-plugins
SSHCC_PLUGIN_DIR=~/plugins-ssh ssh-crypto-checker servidor
```

### Conformance

```bash
# All the standards (the default, without --profile)
ssh-crypto-checker servidor.example.com

# Evaluate only the profiles you care about       # --profile
ssh-crypto-checker -f inventario.txt --profile ens,pci-dss-4

# A specific edition of a standard                # --profile ID@edition
ssh-crypto-checker servidor --profile bsi-tr-02102-4@2026-01

# Your platform's STIG (see --list-profiles for all 15)
ssh-crypto-checker servidor --profile disa-stig-rhel-9-ssh

# Fail if any does not conform                    # --require-profile
ssh-crypto-checker -f inventario.txt --require-profile pci-dss-4

# Require conformance AND tolerate no high findings (independent gates)
ssh-crypto-checker -f inventario.txt --require-profile pci-dss-4 --fail-on high
```

### History and comparison

```bash
# Accumulate every scan                           # --history
ssh-crypto-checker -f inventario.txt --history historico.jsonl

# See how the estate has moved                    # --history-report
ssh-crypto-checker -f inventario.txt --history historico.jsonl --history-report

# Compare against an earlier report               # --compare
ssh-crypto-checker -f inventario.txt --compare base.json

# ...or against the latest entry of the history file
ssh-crypto-checker -f inventario.txt --compare historico.jsonl

# Fail if anything got worse, even if still conforming  # --fail-on-regression
ssh-crypto-checker -f inventario.txt --compare historico.jsonl --fail-on-regression
```

### Exit code in CI

```bash
# Fail on findings of high severity or worse      # --fail-on
ssh-crypto-checker -f inventario.txt --fail-on high

# Never fail because of findings (the default)
ssh-crypto-checker -f inventario.txt --fail-on never
```

### Complete recipes

```bash
# Daily audit in CI, with history and regression detection
ssh-crypto-checker -f inventario.txt --all-checks \
    --history /var/lib/sshcc/historico.jsonl \
    --compare /var/lib/sshcc/historico.jsonl --fail-on-regression \
    --format json,html -o informes/$(date +%F) --fail-on high --quiet

# Deep audit of one server, with access
ssh-crypto-checker servidor.example.com --all-checks --audit-config \
    --user auditor -i ~/.ssh/auditor --max-startups --notes

# A whole estate behind a bastion, exporting metrics
ssh-crypto-checker -f interna.txt -J bastion --all-checks -c 24 \
    --format openmetrics -o /var/lib/node_exporter/ssh.prom

# Evidence for a PCI DSS audit
ssh-crypto-checker -f inventario.txt --profile pci-dss-4 \
    --format inventory,html -o evidencia/$(date +%F)

# Check an ssh_config before deploying it
ssh-crypto-checker servidor.example.com --client-config ./ssh_config.nuevo -s
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything scanned and nothing exceeds `--fail-on` |
| `1` | There are findings at or above `--fail-on`, a required profile is not met, or there was a regression with `--fail-on-regression` |
| `2` | Usage error, or the policy or the history file could not be loaded |
| `3` | Some server could not be scanned |

```bash
ssh-crypto-checker -f inventario.txt --fail-on high
case $? in
    0) echo "todo en orden" ;;
    1) echo "hay hallazgos que atender" ;;
    2) echo "error de uso" ;;
    3) echo "some server did not respond" ;;
esac
```

---

## Authenticated configuration audit

Everything above is visible from the network. **Most real misconfigurations are
not.** `--audit-config` enters the server with the inventory's credentials and
reads its effective configuration —what `sshd -T` actually resolves, not the
file—, delegating the connection to the system's `ssh` client (the password, if
any, goes via `SSH_ASKPASS`, never to disk). The account needs to be root or have
passwordless sudo for `sshd`.

```bash
ssh-crypto-checker -f inventario.txt --audit-config
```

Beyond sixteen directives (`PermitRootLogin`, `PasswordAuthentication`, the
forwardings…), it inspects what no directive captures: permissions and owner of
the host keys and the `sshd_config`, **every** account's `authorized_keys`
(expired entries, no-expiry ones, short or obsolete-type keys), user private keys,
`/etc/ssh/moduli`, the distribution package (its changelog settles by-version
advisories) and `Match` blocks resolved with context. `--audit-client` does the
same for this machine's `ssh_config`.

The two design decisions, the full list of what it inspects and how to add a check
(they are data, with the `expect` grammar) are in
[`docs/politica-configuracion.md`](politica-configuracion.md).

---

## Limitations and legal notes

- **Scan only servers that are yours or that you have express authorization
  for.** The connection is harmless, but it is still an unsolicited
  connection.
- **It leaves traces in the logs.** Every target generates at least one entry
  of the form `Connection closed by <ip> port <n> [preauth]`, plus one per
  host key family. With `--no-host-keys` this drops to a single one.
- **SSHv2 only.** SSHv1 is obsolete and is rejected with an explicit message.
- **It does not check what cannot be seen from outside.** Authentication
  methods, `PermitRootLogin`, `AllowUsers`, patched versions… are not visible
  before authenticating. This complements, not replaces, reviewing the
  `sshd_config`.
- **Version-based advisories are indicative.** Debian, Red Hat and company
  apply patches without changing the advertised version number.
- **The primitives in `crypto/` are not constant-time** and are only good for
  generating a throwaway ephemeral key. Do not reuse them to protect real
  traffic; the warning is in the package's docstring.

---

---

## License

MIT. See [LICENSE](../../LICENSE).
## Extension guides included

The index of the extension manuals is [`extender.md`](extender.md); these are
its guides, installed beside this manual:

- [`auditoria-integridad.md`](auditoria-integridad.md)
- [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
- [`plugin-check.md`](plugin-check.md)
- [`plugin-fleet.md`](plugin-fleet.md)
- [`plugin-vulnerability.md`](plugin-vulnerability.md)
- [`plugins.md`](plugins.md)
- [`politica-algoritmos.md`](politica-algoritmos.md)
- [`politica-configuracion.md`](politica-configuracion.md)
- [`politica-normativas.md`](politica-normativas.md)
- [`politica-puntuacion.md`](politica-puntuacion.md)
- [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md)
- [`politicas.md`](politicas.md)
- [`desarrollo.md`](desarrollo.md)
- [`uso-avanzado.md`](uso-avanzado.md)
