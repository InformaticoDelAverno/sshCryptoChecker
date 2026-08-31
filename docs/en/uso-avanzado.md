# Advanced usage manual

> Back to [`README.md`](README.md). Every option also has its example in the README "Recipe book".

## Comparing against an earlier scan

A report says how a server stands today. What you usually need to know is
**what changed**: what appeared since the last audit, what got fixed, and what
quietly got worse after a package update nobody announced.

`--compare` takes an earlier JSON report as a baseline:

```bash
# Save the baseline
ssh-crypto-checker -f inventario.txt --format json -o base.json

# ... weeks later ...
ssh-crypto-checker -f inventario.txt --compare base.json
```

```
Changes since the baseline
base.json, scanned 2026-07-01T09:12:44+00:00

127.0.0.1:2201: regressed, grade A+ -> C
127.0.0.1:2201: NEW [medium] Weak encryption algorithm(s) offered
127.0.0.1:2201: NEW [medium] CVE-2008-5161: CBC plaintext recovery
127.0.0.1:2201: now offers cipher: aes128-cbc
127.0.0.1:2201: no longer offers cipher: aes256-ctr
```

It reports:

- **New and resolved findings**, by identifier, not by text.
- **Grade movement**, saying whether it improved or got worse.
- **Algorithms added and withdrawn**, by class.
- **Host key changes**, which on a server that has not been reinstalled are
  reason to stop and find out why.
- **New servers** and **servers that were in the baseline and no longer appear**.

The comparison is done over the JSON, so the baseline can be a stored artifact
from an earlier CI run; the tool does not need to store anything.

### History: the series, not just the jump

`--compare` answers "what changed since that report". What it cannot answer is
"since when has this been the case", because a baseline file is a single point.
`--history` accumulates each scan into one file, one line per run:

```bash
ssh-crypto-checker -f inventario.txt --history historico.jsonl --history-report
```

```
Scanned                     Hosts    Avg  Vuln  Crit  High
2026-06-01T03:00:11+00:00  26/27     71.4    18     3    11
2026-07-01T03:00:09+00:00  26/27     74.2    16     1     9
2026-08-01T03:00:14+00:00  27/27     79.8    12     0     6
```

Each line is a complete report, so **`--compare` accepts the same file** and
uses its most recent entry: keeping a series does not force you to also keep a
separate baseline.

```bash
ssh-crypto-checker -f inventario.txt --history historico.jsonl \
    --compare historico.jsonl --fail-on-regression
```

It is JSON Lines and not an array, because appending to an array forces
rewriting the file, and a scan interrupted midway through that rewrite leaves
you **with no history**. A corrupt line is skipped: a file written over months
cannot become entirely unreadable because of one truncated write.

With `--fail-on-regression` the process exits with code 1 if any server got
worse, even if its absolute state is still above `--fail-on`. It is the
difference between "this does not comply" and "this has got worse", and on a
large fleet the second is the one you catch in time:

```yaml
auditoria-ssh:
  script:
    - ssh-crypto-checker -f inventario.txt --format json -o informe.json
                         --compare base.json --fail-on-regression
```

---

## Auditing the client

Everything else in this tool judges the server. But a permissive client undoes
much of the work: the strongest host key in the world, on the best-configured
server, is **not checked at all** if the client was told to accept anything.

```bash
ssh-crypto-checker servidor.example.com --audit-client
```

`ssh -G` is to the client what `sshd -T` is to the server: it resolves the
system file, the user file, every `Host` and `Match` block and the compiled-in
defaults, and prints what that connection would actually use. It asks about a
specific destination **on purpose**: a `Host` block can relax the settings for
one target without anything global giving it away. It opens no connection.

| Check | Why it matters |
|---|---|
| `StrictHostKeyChecking no` | **Critical.** It connects to whatever answers. It is the whole defense against an attacker on the path |
| `UserKnownHostsFile /dev/null` | **Critical.** Every connection is the first, so a key change can never be noticed |
| `ForwardAgent yes` | Whoever has root on the destination server can authenticate as you everywhere |
| `ForwardX11Trusted yes` | The remote host can read keystrokes meant for other windows. It is the default on Debian |
| `IdentitiesOnly no` | You offer every key to every server: a map of where you have access |
| `HashKnownHosts no` | A cleartext `known_hosts` is the list of where to go next from a compromised machine |
| `PermitLocalCommand yes` | Local code execution if someone else can write your configuration |
| `CheckHostIP no` | You are not warned when a known name starts resolving somewhere else |
| `VerifyHostKeyDNS yes` | It is the precondition for `CVE-2025-26465`; it is only sensible with validated DNSSEC |

In addition, **the client's own algorithms** are classified with the same
policy as the server's. Negotiation picks something both ends accept, so a
client that still offers `3des-cbc` will use it against any server that permits
it — hardening the servers does not remove it, hardening the client does.

The checks are **data**, just like the `sshd_config` ones: they live in
`ssh_config_checks` inside `algorithms.json` and use the same `expect` schema.

---

## Scanning behind a bastion

A segmented network forces you to hop through an intermediate host. `ProxyJump`
does not help here: that option belongs to the ssh client, and on the scan path
**there is no ssh client** — the tool opens its own sockets, which is exactly
what lets it see what a server offers without authenticating.

So the hop is done the other way around. With `-J` a local port forward is
opened through the bastion and the scan connects to the local end:

```bash
ssh-crypto-checker -f inventario.txt -J bastion.example.com
```

The report **still names the real target**: `127.0.0.1:41337` is of use to
nobody. It also adds how it was reached.

The bastion is an ssh destination, so the normal thing is to have it in
`~/.ssh/config`. Otherwise it accepts `[user@]host[:port]`, and `--jump-option`
passes loose options to that connection (in the `=` form, because the value
starts with a hyphen):

```bash
ssh-crypto-checker servidor.interno -J ops@bastion:2222 \
    --jump-option=-oIdentityFile=~/.ssh/bastion
```

Three decisions worth knowing about:

- **`--max-startups` is skipped behind a bastion.** The probe counts how many
  unauthenticated connections the server tolerates, and each one would also be a
  channel of the bastion session: what would come back is the lower of the two
  limits, presented as if it were the target's. A wrong number is worse than no
  number.
- **The authenticated audit reuses the same forward**, it does not make its own
  hop. `ssh -J` is no good for that: ssh builds the inner command itself and
  almost none of our options reach it, so the bastion's host key could not be
  handled as the user asked.
- **The target's key is recorded with `HostKeyAlias`**, under its real name.
  Without that, `known_hosts` would fill up with entries for ephemeral ports and
  the server's key would never be checked against anything.

> The tunnel **does not weaken** the check of the bastion's key. It uses the ssh
> configuration of whoever runs it; in a tool that audits SSH security, skipping
> that for convenience would be hard to defend.

---

## Server and credentials file

One target per line. `#` starts a comment. Whatever follows the first
space-separated token is used as the **label** in the report (there is a sample
inventory ready to copy in [`examples/`](../../examples/README.md)):

```
# Inventario de producción
web01.example.com:22        frontend web
web02.example.com:22        frontend web
192.0.2.10                  base de datos
[2001:db8::1]:2222          router de borde
bastion.example.com         # solo comentario, sin etiqueta
```

```bash
ssh-crypto-checker -f inventario.txt
```

It can be read from standard input with `-f -`:

```bash
grep -h '^Host ' ~/.ssh/config | awk '{print $2}' | ssh-crypto-checker -f -
```

Duplicates (same host and port) are removed. A malformed line does not abort
the file: it is reported on `stderr` and processing continues.

### How many servers fit: measured, not estimated

Measured on this machine, not guessed at. The first table points at closed
ports, so it is the cost of the framework itself with no network in between:

| Targets | Time | Peak memory | JSON report |
|---|---|---|---|
| 200 | 0.9 s | 29 MB | 286 KiB |
| 1,000 | 1.8 s | 36 MB | 1.4 MiB |
| 5,000 | 6.0 s | 72 MB | 7.1 MiB |

Linear in both: about **27 MB of base and ~9 KB per unreachable target**.
Nothing grows in a strange way, and nothing is left behind.

The second is a **real** scan of the lab's 96 servers, with SSH greeting, host
key and all the probes:

| `-c` | Time | CPU |
|---|---|---|
| 1 | 37.9 s | 10 % |
| 4 | 19.5 s | 25 % |
| 8 | 18.7 s | — |
| 16 | 17.9 s | 31 % |
| 32 | 17.5 s | — |

And here is what matters, because it is not what people assume: **going from 8
to 32 fixes nothing**. The CPU stays at 31 %, so it is not that the machine has
no more to give. The floor is set by **a single target**: the lab server that
accepts the connection and never says anything always costs 16.1 s with `-t 8`,
because it exhausts the timeout twice in a row. As long as that one is there,
the scan cannot finish sooner.

> **The lever is `-t`, not `-c`.** Raising concurrency spreads the work; only
> lowering the timeout lowers the floor. With `-t 3` that same server costs 6 s
> instead of 16, and a large scan finishes sooner — at the price of risking
> marking a genuinely slow server as unreachable.

A **real and complete** target takes about 48 KiB in the JSON and about 155 KB
in memory for the duration of the scan, because the whole report is built in
memory before being written. That is where the practical ceiling comes from:
**about 5,000 real servers per run come in around a gigabyte**. For a larger
fleet, split the inventory and scan in batches; there is no *streaming* output.

### Per-server options

After the target you can put `key=value` pairs. Anything that is not a
recognized option accumulates as a label, so the old format keeps working:

```
# Inventario con credenciales
web01.example.com:22   user=admin auth=key key=~/.ssh/id_ed25519   frontend web
db01.example.com       user=svc auth=password password-env=DB01_PW
router.example.com     auth=none   router de borde
alt.example.com        port=2222 label=nodo alterno
192.0.2.10             servidor heredado
```

| Option | Meaning |
|---|---|
| `user=` / `username=` | Account to authenticate with |
| `auth=` | `none` (anonymous), `key`, `password` or `any` (default) |
| `key=` / `identity=` | Private key file |
| `password-file=` | File to read the password from (first line) |
| `password-env=` | Environment variable to read it from |
| `port=` | Port, an alternative to `host:port` |
| `label=` | Explicit label |

The same values can be given as **script parameters**, and act as defaults for
the targets that do not define them:

```bash
ssh-crypto-checker -f inventario.txt --user auditor --auth key -i ~/.ssh/id_ed25519
ssh-crypto-checker -f inventario.txt --auth password --password-env SSH_PW
```

> 🔐 **A literal password in the inventory is not allowed.** Only
> `password-file=` and `password-env=`, so the file can be versioned without
> leaking a secret. The password is read **at the moment it is used**, it is
> never stored in the result object, and any field whose name suggests a secret
> is replaced by `[redacted]` when the report is serialized.

---

## Additional remote checks

Beyond the algorithms, there are things that can be verified **without
credentials**. They are off by default because they are more intrusive or
slower:

```bash
ssh-crypto-checker servidor.example.com --auth-methods --sshfp --login-grace
ssh-crypto-checker -f inventario.txt --all-checks      # all three at once
```

### `--auth-methods` — accepted authentication methods

The most valuable thing you can learn without getting in. The list travels in
`SSH_MSG_USERAUTH_FAILURE`, which the server only sends **after** encrypting the
session, so the tool completes a real key exchange (X25519, the three NIST
curves or *group exchange*), derives the session keys and encrypts — all in pure
Python, with no dependencies. Then it asks to authenticate with the `none`
method, which is designed to be rejected and return the list.

It supports the four modes SSH uses, so it **works against any server**, from a
modern one that only offers AEAD to an old one that only offers CBC:

| Mode | Verified against |
|---|---|
| AES-CTR | NIST SP 800-38A F.5.1 |
| AES-CBC | FIPS 197 (inverse cipher) |
| AES-GCM | NIST GCM Test Case 3 and 4 |
| ChaCha20-Poly1305 | RFC 8439 §2.5.2 and the original ChaCha20 vector |

MAC in both orders (classic and *encrypt-then-MAC*), including `hmac-sha1` and
`hmac-md5` as a last resort: using a broken MAC for a throwaway packet is not a
security decision, it is the difference between being able to audit an old
server or not.

It detects what no cipher list protects against:

- **`password` or `keyboard-interactive` enabled** → exposure to brute force,
  which is the most common way into an SSH.
- **`none` accepted** → the server gives a session to anyone. A critical
  finding.
- **`hostbased`** → the client machine is trusted, not the user.

> ⚠️ Unlike the rest of the scan, this **leaves a failed authentication entry in
> the log** of the server and could trigger a `fail2ban` if repeated. That is
> why it is opt-in. With `user=` in the inventory the real account is probed,
> since the methods can vary per user.

### `--sshfp` — fingerprints published in DNS

Checks whether SSHFP records (RFC 4255) exist and whether they **match the keys
the server actually presents**. Without them, a client connecting for the first
time has nothing to verify the key with. It also detects stale records after a
rotation, and warns if the resolver did not mark the answer as DNSSEC-validated
(unsigned, the records can be forged by whoever controls the DNS path). Its own
DNS client, no dependencies.

With `--dns-server ADDR` a specific name server is queried instead of the ones
in `/etc/resolv.conf`, accepting `address`, `address:port` and `[::1]:port`. It
is useful when the records live in an internal zone the machine you scan from
does not use by default, or to check an authoritative server before publishing.
It can be repeated.

```bash
ssh-crypto-checker servidor.interno --sshfp --dns-server 10.0.0.53
```

### `--login-grace` — `LoginGraceTime` observed

Measures how long the server tolerates an unauthenticated connection. It matters
because the documented mitigation for regreSSHion (CVE-2024-6387) is to set it
to 0, which removes the timer and swaps the vulnerability for an exposure to
denial of service. The wait is idle, so with several servers in parallel it
costs almost the same as with one.

### `--known-hosts` — comparison against the local record

Compares the keys with those in a `known_hosts` file, understanding both
cleartext entries and **hashed** ones (`HashKnownHosts`, the default on many
systems, where the name is stored as salted HMAC-SHA1). It detects that a key
**has changed** relative to what was recorded —undocumented rotation or
interception— and keys marked `@revoked` that are still in service.

### `--max-startups` — pre-authentication slots

Opens concurrent unauthenticated connections until the server stops accepting
them. Those slots are what an attacker exhausts to lock out real users, and a
long `LoginGraceTime` makes each one cheaper to hold. **It is a small deliberate
denial of service against the target**, so it is outside `--all-checks` and has
a limit.

### `server-sig-algs` (RFC 8308, automatic with `--auth-methods`)

The signature algorithms the server accepts **from clients**. This is not
visible in the KEXINIT: a server can present a strong host key and at the same
time still accept SHA-1 signatures from its users. It is obtained from the
`SSH_MSG_EXT_INFO` the server sends after encrypting the session.

### Preferred algorithm (automatic)

The **first** of each list is what a permissive client negotiates, so the order
matters as much as membership. If the first is weak or insecure a finding is
emitted, even if further down there are excellent algorithms that will never be
used.

### Shared host keys (automatic)

It needs no option: when scanning several servers, the tool compares the
fingerprints and **warns if two share a host key**. Almost always these are
cloned machines or an image with the key baked in, and it means that whoever
extracts the private key from one can impersonate all of them. It is only
visible by looking at the whole fleet, so it is decided when the scan finishes.
