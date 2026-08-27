# Development manual

> The repository map and the user guides are in [`README.md`](../../README.md).

## Structure

```
ssh_crypto_checker/
├── cli.py             Command-line interface and exit codes
├── targets.py         Target parsing (host:port, IPv6, files)
├── ssh_protocol.py    SSH transport layer: banner, KEXINIT, host keys
├── crypto/            Minimal primitives to complete an exchange
│   ├── x25519.py      X25519 (RFC 7748)
│   ├── ecc.py         NIST P-256/384/521 curves
│   └── dh.py          MODP groups 1 and 14 (RFC 2409/3526)
├── policy.py          Loading and validation of the policy file
├── models.py          Shared dataclasses and JSON serialization
├── analysis.py        Classification, findings, scoring and recommendations
├── scanner.py         Concurrent orchestration
├── reporting/         One renderer per format
│   ├── common.py      Colors, tables, text wrapping
│   ├── console.py     Terminal (and blocks reused by text.py)
│   ├── text.py        Plain text
│   ├── json_report.py JSON
│   └── html.py        Self-contained HTML
└── data/
    └── algorithms.json  The default policy
```

Data flow:

```
targets.py  ->  scanner.py  ->  ssh_protocol.py   (network)
                     |
                     v
                analysis.py + policy.py           (judgement)
                     |
                     v
                 models.py                        (TargetResult)
                     |
                     v
                reporting/*                       (presentation)
```

Design rules worth respecting:

- **Zero runtime dependencies.** It must work with the Python that any
  distribution ships.
- **No security decision in the code.** If you are writing the name of an
  algorithm inside a `.py`, it probably belongs in `algorithms.json`. The
  legitimate exceptions are `ssh_protocol._CLIENT_CIPHERS` (what the scanner
  *offers* so that negotiation works, deliberately broad) and `_SUPPORTED_KEX` /
  `_PQ_KEX_CLIENT_BYTES` (what the scanner knows how to run).

### Post-quantum-only servers

A server that only offers ML-KEM or sntrup761 cannot be negotiated with classical
cryptography, and until now that meant **no host key**: no fingerprint, no size,
no certificate, no comparison against SSHFP.

You do not need to implement the KEM to fix it. The server puts its host key **as
the first field of the response**, before the ciphertext and before the
signature, so it is enough for it to answer. And it answers if the client sends
it a *well-formed* key: FIPS 203 only requires the 12-bit coefficients to be
smaller than q, and that is achieved by choosing the coefficients rather than the
bytes. With random bytes the probability of passing the check is (3329/4096)^768,
that is, zero.

Nobody holds the corresponding private key and it does not exist: this buys a
response, not a session. That is why the post-quantum method goes **last** in the
order of preference —if there is a classical one it is used instead, which does
give a shared secret— and why the code explicitly refuses to go on when someone
asks it for an authenticated session over it, rather than setting up one that
would decrypt to noise. The fingerprint obtained this way is compared in the
tests against that of the classical exchange against a server that offers both.
- **Renderers do not judge.** They receive an already-analyzed `TargetResult`
  and only present it. All the logic lives in `analysis.py`.
- **The errors of one target do not abort the scan.** `scan_target` captures its
  own exceptions and returns a result with `status=error`.

## End-to-end test coverage

```bash
pip install coverage        # the only development dependency; the tool has none
python3 -m coverage run --branch --source=ssh_crypto_checker -m unittest tests.test_docker_lab
python3 -m coverage report -m
```

**Two things are measured separately, and they answer different questions.**

| Measurement | How | What it answers | Figure |
|---|---|---|---|
| Full suite | `-m unittest discover -s tests -t .` | How much of the code *some* test runs | **100%** |
| The lab only | `-m unittest tests.test_docker_lab` | How much has been run **against real SSH servers** | **~90%** (642 statements and 132 branches unreached, listed one by one) |

The first is **100% of statements and 100% of branches, without a single
exclusion**: `.coveragerc` has no `exclude_also` and no `exclude_lines`. There is
nothing in that file that tells coverage to look the other way.

The second is the demanding one, and it is the one that has found the bugs.
Passing the whole suite inflates the number with unit tests against doubles; a
path that only a double has walked is not a path known to work against a server.
Of the statements it is missing, **each one is justified below one by one** and
with the check alongside it, not by categories.

Measuring it exposed the biggest gap that was left: **the command line was at
0%**. The end-to-end tests called `scan()` directly, so argument parsing, the
inventory file, writing each format, comparison against a baseline, the history
and **the exit codes** —what anyone who scripts this uses— were only tested
against doubles. There is now a class that drives the real CLI against the lab.

The same thing was happening underneath: the scanner implements AES-CTR, AES-GCM,
ChaCha20-Poly1305 and CBC because it has to **encrypt real packets** to read the
authentication methods, and every auditable server accepted `aes256-ctr`. The
other three transformations were only tested against known vectors, never against
a server that would reject an incorrect response. There are three more servers
that offer a single cipher each.

**`.coveragerc` no longer has an exclusion list, and that is the goal.** An
exclusion is a piece of code that nobody has ever run, with a note beside it
saying not to worry. The ones there were disappeared one by one: some because the
guard was redundant, others because the code was restructured so that the check
*is* the loop rather than a branch beside it —in `crypto/x25519.py` the last
conditional exchange turned out to be dead under the *clamping*—, and the rest
because they were perfectly reachable as soon as someone tried: an interpreter
without `tomllib`, an already-closed stream, an `ssh` that ignores `SIGTERM`.

**The threshold (`fail_under`) in `.coveragerc` is at 100**, because the figure
is at 100. `coverage report` fails if it drops, so a change that stops exercising
a path is noticed at once and not a year later. Lowering it demands an
explanation in the commit message.

### And the second figure has its own gate

A threshold on the percentage would not have served for the lab measurement: **82
statements out of 6745 can turn into 120 without the 98% moving**. So what is
stored is not the percentage but **the exact list of lines the lab does not
reach**, in `tests/lab-coverage-baseline.json`, identified **by their text** and
not by their number —the number moves with the first edit, and a baseline that
has to be regenerated every other day teaches you to regenerate it without
reading it—.

```bash
python3 -m coverage run --rcfile=.coveragerc -m unittest tests.test_docker_lab
python3 -m coverage json --rcfile=.coveragerc --fail-under=0 -o coverage-lab.json
python3 tools/lab_coverage_gate.py
```

It fails in both directions, and that is what matters:

| What happens | What the gate does |
|---|---|
| A line the lab does not reach appears | **Fails**, and names it. Either the lab is given a way to reach it, or it enters the list **with its reason in this README** |
| A line on the list becomes covered | **It fails too.** A list with permissions nobody uses any more stops being true, and would mask the next line written the same way |

On top of that there is a ceiling written in `tests/test_coverage_gates.py`
(`MAX_UNREACHED_STATEMENTS`, `MAX_UNREACHED_BRANCHES`): lowering it costs nothing,
raising it forces you to touch a test and to say why in the commit. That file
also checks that `.coveragerc` still has `fail_under = 100`, with branches, and
**without an exclusion list** —the strongest claim of this section, which with
nobody watching it is the first to be lost—, and that each line of the baseline
list **still exists** in the file it names.

And it tests the gate itself with a falsified measurement in both directions,
because a gate nobody tests is a gate that always says yes.

### The lab also runs the tool, not only points it

Everything else here points the scanner at a server. There is a container
(`lab/runner/Dockerfile`) that does the opposite: it **runs the scanner**, with
the repository mounted inside. It is the only way for the lab to control the
**environment** rather than the server — a machine with no name server, one whose
`/etc/resolv.conf` cannot be read, an installation missing its own policy file.
None of that can be staged from the machine running the tests: the process cannot
replace `/etc/resolv.conf`, and it needs the policy file that the third case
removes.

It runs **Python 3.12 on purpose, not the newest**. Since 3.14 annotations are
evaluated lazily (PEP 649); before that they are evaluated when the function is
defined. An annotation that names a type nobody imported is invisible in 3.14 and
a `NameError` in everything earlier — and the loader responds to that by
**discarding the check**, printing a warning line and going on. Two *builtin*
checks were exactly like that, one of them the classification of *critical*
severity algorithms: on the Python a real user has, the tool reported too little
and said so in passing. This container is the oldest thing in the lab and it is
here to keep saying it.

### That a line runs does not mean anyone is watching it

Coverage records that the interpreter went through a line, not that anyone would
notice if that line did something else. A 100% built with lines like that
protects nothing, so there is a second question and a tool that answers it:

```bash
python3 tools/mutation_gate.py            # check against the baseline
python3 tools/mutation_gate.py --update   # record what survives now
python3 tools/mutation_gate.py --only policy   # one module, while you work
```

It breaks the code on purpose, one small change at a time, and runs the tests.
What makes a test fail is **dead**: someone was watching. What nobody notices
**survives**, and it is a line the suite visits without looking.

| The change | And it is a real bug |
|---|---|
| `<` becomes `<=` | an off-by-one at a boundary |
| `==` becomes `!=` | an inverted condition |
| `and` becomes `or` | a widened guard |
| `0` becomes `1` | a changed default value |
| `+` becomes `-` | an arithmetic slip |
| **a `raise` disappears** | a swallowed error: bad input accepted, broken policy loaded, malformed packet read as if it made sense |
| **a `return` returns `None`** | a forgotten answer: whoever uses it finds out, whoever ignores it never used it |

What it found, the first time it was really run: **nothing checked that a host
key below the minimum raised the flag** that caps the grade at D. Nor that an
unreadable key did *not* count as small. Nor that a Diffie-Hellman group of
exactly the minimum was not weak. Nor the three exact conditions of the word
`secure`, which nobody had separated. Fourteen gaps in the grade computation, all
run by the suite and none of them watched.

**Two warnings, both learned by getting it wrong:**

A mapping of source file to test module —which was there for speed— is an
invitation to get it wrong **in the flattering direction**. The FIPS-197 vectors
live in `test_remote_checks.py`, not in `test_crypto.py`, so the AES mutants were
judged by tests that do not touch the cipher and fifty-two "survived". There is
no mapping: each mutant faces the whole suite, and parallelism buys the speed the
mapping was trying to buy.

**Where it stands today:** 3508 mutants, 3475 killed, 33 survivors. That 33 has
to be read with its history, because the number that was there before was
**zero, and the zero was a lie twice over**. The first: the gate copied two
directories into the sandbox and the suite needed more, so twenty tests erred in
every sandbox and **every** mutant was recorded as caught; fixing it turned that
zero into 748, and from there it dropped for real to 443. The second, subtler
one: the gate reused the sandbox between mutants **without `-B`**, and in a `/tmp`
on ext3 an edit of the same size (`==`↔`!=`, `+0`↔`-0`, `and`↔`or`, one digit for
another) leaves date and size intact, so CPython ran the old `.pyc` and the
mutation **never executed** — and too short a deadline recorded as a catch a
suite that was slow but passing. With `-B` and 600 seconds the fast pass is
deterministic, and the honest figure is not zero: the suite kills 3475 of 3508,
and the 33 that remain **do not change anything a caller can observe** — a
comparison with a guard, a zero-weight term, a `maxsplit` read at `[0]`,
projective coordinates of the Montgomery ladder, a keystream block that is
discarded, a `-> bool` used only for its truth —. Each one is **proven
equivalent** by exhaustive differentiation or by fuzzing through the real
function, and the 33 are listed by file and line in
`tests/mutation-baseline.json`; the gate fails the moment survivor number 34
appears.

That these three figures stay true does not depend on someone remembering to edit
them: `tests/test_documentation_matches_the_policy.py` reads them from this
paragraph and compares them against the survivors file and against the gate's
constant.

That does not mean "the tests are perfect". It means exactly what it measures:
**none of the seven changes it knows how to make —a comparison, an `and`, a
boolean, a constant, an arithmetic operation, a `raise` that disappears, a
`return` that returns `None`— survives**. What it does not measure: larger
changes, text strings and substituted calls.

It takes **171 minutes**, and that is why it reports where it is every hundred
mutants: a tool that prints nothing for three hours is a tool people kill, and
then it is a tool nobody runs.

**And the lab has the last word.** A survivor candidate —something the unit suite
did not kill— is handed to `DockerLabTests`, which scans the 95 servers with all
the probes in 18 seconds, before writing it into the list. It does not run for
every mutant, only for the ones that arrive alive, which is the only place it can
change the answer: a survivor has to mean "nothing catches it", not "the fast
half does not catch it". Today none arrives, so it costs nothing.

> Honestly: **it has not yet caught anything the unit suite let through**. Three
> mutations chosen to favor it were tried —the format the remote script asks for,
> a section marker, the banner cleaner— and all three were also caught by the
> unit tests. It is there as insurance, not as a demonstrated improvement.

And a survivor is **confirmed with the machine quiet** before it is believed.
Fourteen suites in parallel is exactly how a test that would have caught
something runs out of time, and a gate that gives false alarms is a gate people
learn to ignore.

In CI there are two jobs. `coverage:gates` costs seconds and runs **on every
push**: it checks `.coveragerc`, the baseline list and the gate itself.
`coverage:lab` brings up the whole lab and takes both measurements —the lab's
against its baseline list, and the full suite's against `fail_under = 100`—; as
that is around 130 containers and most of them compile, it runs **by hand or on a
schedule**, not on every push.

What the exclusion list said was unreachable turned out not to be, and chasing it
found bugs:

| What the exclusion said | What happened when it was removed |
|---|---|
| Policy validation (`policy.py`) | Reached with `--config` and a broken file. It turned out that an `entries` with the wrong type blew up with `AttributeError` instead of `PolicyError` |
| Plugin loader errors | Reached with a directory of broken plugins: `lab/lab-plugin-broken` has one file per reason. A directory named `something.py` came out as `IsADirectoryError` |
| `except Exception` in the thread pool | Tested by simulating the defect it contains. It was removed as "unreachable" and the next run lost a scan of 41 servers to a one-line `NameError` |
| Terminal detection in `reporting/common.py` | Reached by assigning a pty to the test |

The code that contains defects is not reached with any *input*, but it is tested
**by simulating the defect**. That no input exists to trigger it is not the same
as not being able to test it.

### What the lab cannot reach, and why

Each remaining line has been reviewed **one by one**, not by categories, and the
reason is verified where it could be verified. What once figured here as
unreachable and is covered today already takes up more room than what remains:

| What this list said | What it turned out to be |
|---|---|
| A hostile encrypted session "would require implementing all of SSH" | It requires considerably less, because the scanner is a scanner: **it does not verify the host key signature**, so a lab server needs a curve, a key schedule and a cipher, and can sign with random bytes. `lab/exotic/session_server.py` is 380 lines and covers the three responses to the authentication request |
| The reset arrives as end of file "because of a race" | It was not a race: it was the Docker proxy, which ends the connection when publishing a port and delivers an orderly end whatever the container did. Twenty of twenty against a local socket, **zero of ten via the published port**, six of six against the container's address |
| The connection cap cannot be exhausted | It can: a server that closes its listener while full rejects the connection instead of accepting it and going silent. Again it is only seen talking to the container directly |
| A report with nothing to report does not exist in the lab | It exists with a policy with no rules and a post-quantum server: grade A+, zero findings |
| `to_jsonable` never sees any `bytes` | It sees them if a plugin puts them in. Asking where they could come from found that **four formats blew up** when writing them |
| The authentication probe cannot run out of shared secret | It can: X25519 has no encoding to reject, so a 31-byte public value throws nothing — there is simply no secret |
| Four more, already in the previous review | The host-key probe cap, a shared secret of zero, the clock of the grace measurement and the line wrapping of an empty text |
| "The argument validation of a primitive is reached by no server" | True for keys, IVs and counters. **False for the length of a CBC packet**, which travels encrypted and is chosen by the peer: twenty leaves eight, and eight is not a block |
| "The plugin contract cannot be created by the lab" | `analyse()` stops before running a check with no offer, on *that* path. The **fleet view** keeps a view for each result, including the ones that failed: no offer and no assessment. A fleet plugin that reuses the builtin checks drives exactly that view |
| "The test process cannot replace `/etc/resolv.conf`" | It cannot. **A container can**, and now the lab has one that runs the tool instead of receiving it. Three lines of the environment reached with the real CLI — and along the way it turned out that two *builtin* checks did not load on any Python earlier than 3.14 |

What remains, with the reason verified:

| Group | Example | Why the lab does not reach it, and how it was verified |
|---|---|---|
| Argument validation of the primitives | `raise ValueError("AES keys are 16, 24 or 32 bytes long")` | The key, block, IV and counter sizes **are derived by the scanner** from the exchange hash. A server chooses none of them. **Except one**: the length of a CBC packet travels encrypted, is chosen by the peer and has to leave a whole number of blocks — there is a server that says twenty and leaves eight, and that line is no longer here |
| **DNSSEC signature verification** | `dnssec.py`, `crypto/{ec,ecdsa,ed25519,rsa}.py` | The `lab-dns` **never signs** —that is the normal state on the internet, and it earns a warning—, so no RRSIG is ever verified against it: chain validation and the four signature checks are exercised only by the unit fixtures (`test_dnssec.py` and friends, with signed fixtures). That is ~380 lines, the bulk of the 642; the day the lab serves a genuinely signed zone, they drop |
| Curve arithmetic in its edge cases | `is_on_curve(None)`, negative scalar | The server's point passes through the *on-curve* check **before** the arithmetic; the point at infinity and negative scalars are produced by nobody |
| Guards the caller itself discards | `_sha256_hex` with a fingerprint that does not start with `SHA256:` | The loop that calls it already skips keys with an error and without a fingerprint, so the fingerprint always has that form. The same with `strength_for_modulus(None)` and `strength_level(None)` —the three callers filter first—, with `assessment("kex")` —the loop builds an assessment for **each** of the five classes— and with a certificate without dates: the object is only built after reading them, **verified by truncating the blob at each field boundary** |
| Guards the prior selection discards | `_kex_hash` with a method without a known hash, `_run_key_exchange` with an unimplemented one | `select_kex_for_probe` only returns names from the two lists the scanner knows how to drive, so neither of the two is reached. The same with `parse_ext_info`/`parse_kexinit_payload` on the wrong packet —they are called after `read_message(TYPE)`—, with the `_mac` without a MAC —only the AEAD ciphers have none, and those do not go through there— and with `parse_host_key_blob` without an algorithm: the two callers always pass one |
| Defect detectors that cannot be fed | `Ansi` with a style that does not exist, a metric declared twice | The style names and the metrics are literals in the code itself, each written once. They exist so that a typo in a renderer fails out loud, and a typo is not an input |
| Guards the policy loader discards | `Policy.lookup` with a class that does not exist | The loader **requires the five classes** (verified by deleting one: it rejects the file). Likewise with the empty grade scale, with unknown expectations and with the final `return True` of `check_expectation` |
| Defect containment | `except Exception` around the audit parsing | No *input* reaches it: **4809 malformed blobs** were passed to `parse_host_key_blob` —truncated at every byte, with absurd and random length prefixes— and **none** raised an exception. It is tested by simulating the defect, not by feeding it |
| API for whoever imports the package | `scan([])`, `analyse()` on a failed result, `render()` with an invented format, `Tunnel.close()` without having opened | The CLI rejects the empty inventory before reaching it (verified by running it), `scan_target` returns before analyzing when the status is not OK, the CLI names the formats and rejects the one it does not know before rendering, and `open_tunnel` only returns open tunnels. The empty summary table is the same thing seen from the report: with no targets there are no rows |
| A half-finished `nameserver` | A `nameserver` line with no address after it | The resolver file **is** controlled now, from the container that runs the tool: empty and without read permission are two lab cases. A truncated `nameserver` line is the third form and is produced by no resolver |
| A write failure | `_send` with `OSError` | The client's write is one kilobyte and happens **microseconds** after reading the banner: the peer's reset has not arrived yet. Measured with six constructions —close with unread data, `shutdown`, reset with no pause, via the published port and against the container's IP— **0 of 20 in all of them**. It is the failure of a network that cuts the connection between our read and our write, and the lab has no network |
| The web interface in its two containment nets | `except BaseException` around the start of the scan thread, and the connection dropping of `_BoundedServer` above `MAX_CONNECTIONS` | The lab drives the wizard **entirely** (100% of `wizard.py`: it answers the prompts against a lab server and launches the scan, with all the option gates, reprompts and cancellation) and almost all of the web interface (99% of `web/server.py`: `POST /api/scan` against the lab, each format downloaded, plus the validation arms, the token, the private target/DNS filter, the size cap, the 503 concurrency and the store eviction). What remains is two resource-containment nets —exhausting threads/memory when starting the scan, and exceeding 64 simultaneous connections— that are only reached by simulating the failure, not by feeding it; they are in `test_web.py`. The `python -m ssh_crypto_checker.web` is the third: it only runs as a subprocess that blocks on `serve_forever`, and `server.main` is already driven directly |
| The entire MCP interface | `mcp/server.py`, `mcp/__init__.py`, `mcp/__main__.py` | The lab scans **SSH servers**; it does not speak JSON-RPC to an MCP server of its own, so —unlike the web, which the lab does drive via its test— **no** line of the MCP is reached by the lab. It is a third face of the tool, like the web: it is fully covered by the unit suite (`tests/test_mcp.py`, 100% of `mcp/`), which drives the JSON-RPC transport, every method, every tool and the three `SystemExit` exits. Like `web/server.py`, it enters this list because the SSH lab has nothing to exercise it with |

The first group stays: removing the argument validation of a cryptographic
primitive to raise a number would be exactly the opposite of what this project
intends. The rest are open to debate —they are redundant guards or unused
surface, and deleting them is as legitimate as covering them— and every time one
has been deleted it has been with its reason in the commit message, not in an
exclusion list.

### Chasing coverage found a real bug

A rule that named a nonexistent algorithm class —`cyphers` instead of `cipher`—
raised a bare `KeyError` inside the evaluator. Since `scan_target` captures its
own errors, the result was that **every server came out as not scannable**, and
the reason printed pointed at the server instead of at the typo in the policy. A
misplaced character brought down the whole run and blamed the wrong party.

Now it is rejected **when reading the file**, which is where the other errors of
that file are caught, and the message names the invented class and lists the ones
that exist. In addition `offered()` translates any `KeyError` into a
`DetectionError`, as a safety net: a broken rule must cost its own result and
nothing more.

It is the argument in favor of measuring. That path had unit tests and they all
passed; what it did not have was anyone running it against a real server.

## Running the tests

```bash
python3 -m unittest discover -s tests -t .     # everything
python3 -m unittest tests.test_analysis -v     # one module
python3 -m unittest tests.test_crypto.CurveTests.test_order_times_generator_is_the_point_at_infinity
```

No dependencies and no network are needed: `tests/fake_ssh_server.py` brings up a
minimal SSH server on `127.0.0.1` that speaks just enough to be scanned, with
configurable algorithm lists.

The tests in `tests/test_crypto.py` deserve a mention: the constants of the
curves and the primes are not compared against a copy of themselves —that would
detect nothing— but against their mathematical properties. It is verified that
the generator is on the curve, that `n·G` is the point at infinity and that the
Diffie-Hellman moduli are safe primes. A typo in any digit makes the test fail.

## Where each thing lives

| | |
|---|---|
| `analysis.py` | The **orchestrator**: what is run, in what order, and what is done with it. It decides nothing |
| `assessment.py` | The **model**: it classifies, measures strength, computes the grade and the verdict. **It is not extensible by plugins** |
| `plugins/__init__.py` | What a plugin **is**: metadata, return types, the view it receives |
| `plugins/runner.py` | How a plugin's answer becomes a result |
| `plugins/builtin/` | The checks, one per subject |
| `vulnerabilities.py` | The engine of the declarative JSON rules |
| `data/algorithms.json` | The algorithms, the rules and the thresholds |

`plugins/__init__.py` **does not know** what a finding or a report is; `runner.py`
is the only one that does. That separation is what lets you write a plugin against
a small, stable surface while the result types move underneath.

## Adding a check

A check lives in one of two places, and choosing well is half the work. **If it
is decided by comparing something the server announces** —an algorithm name, a
version window, the value of a directive— it is a **declarative rule** in the
policy file, no code: the algorithms and their tags in
[`politica-algoritmos.md`](politica-algoritmos.md), the vulnerabilities in
[`politica-vulnerabilidades.md`](politica-vulnerabilidades.md). The detection
grammar also includes the conditions `auth_method` (an offered authentication
method) and `extension` (an announced RFC 8308 extension), both with
`--auth-methods`.

**If it has to *compute* something** —divide a number, subtract two dates, factor
a modulus— it is a **plugin**: see [`plugins.md`](plugins.md), where the `KIND`
distinguishes a `check` (one server), a `fleet` (all of them at once) and a
`vulnerability` (a published attack with its own identifier). When in doubt, try
a rule first: it runs no code, can be edited by a non-programmer and cannot break
a scan. Both forms are tested against the lab.

## The house rules

Four things the system guarantees, and that it is worth not breaking:

1. **A broken plugin does not break a scan.** Whatever it throws is captured and
   reported, naming the plugin and the exception.
2. **No plugin changes the grade.** There is a test that scans with all the
   plugins and with none and requires `score`, `grade` and `verdict` to match.
3. **Not looking is not not finding.** If a check could not be done, it is said;
   it is never reported as "not affected".
4. **`analysis.py` has no checks.** There is a test that fails if someone adds
   one. They go in a plugin or in the JSON.

## Adding an output format

Create `reporting/my_format.py` with `render(report, policy, options) -> str` and
register it in `FORMATS` and `EXTENSIONS` of `reporting/__init__.py`. The contract
tests in `tests/test_reporting.py` pick it up automatically.

## Style

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy ssh_crypto_checker
```

100-column lines, type annotations on all public functions,
`from __future__ import annotations` in all modules (compatibility with Python
3.9).
