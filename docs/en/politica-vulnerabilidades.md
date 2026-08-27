# Policy manual — vulnerabilities

> Before this, read [`politicas.md`](politicas.md).

A vulnerability is written entirely as data in the `vulnerabilities` list. No
programming is needed, which is why everything that can fit here should go
here.

---

## The shape of an entry

```json
{
  "id": "CVE-2023-48795",
  "name": "Terrapin: truncado de prefijo en el intercambio de claves",
  "severity": "medium",
  "description": "What happens and why it matters, for somebody meeting it cold.",
  "remediation": "Exactly what to do. An order, not advice.",
  "references": ["CVE-2023-48795", "https://terrapin-attack.com/"],
  "affects": "server",
  "detection": { ... }
}
```

| Field | Required | Notes |
|---|---|---|
| `id` | **yes** | Unique. A duplicate is rejected at load time: two detections with the same id cannot both be reported. |
| `name` | **yes** | The report title. |
| `severity` | **yes** | `critical`, `high`, `medium`, `low`, `info`. |
| `description` | **yes** | Write it for the person who will read it at two in the morning. |
| `remediation` | yes in practice | Without it, this is a complaint. |
| `references` | yes in practice | **Without a reference it is an opinion.** |
| `affects` | no (`server`) | `server` or `client`. |
| `detection` | **yes** | The condition. Everything else in this manual. |

---

## The detection grammar

A condition is an object with **one** key. There are five conditions that
look at something and three that combine others.

### `version` — by product version

```json
"detection": {
  "version": {
    "product": "OpenSSH",
    "affected": [ { "introduced": "8.5p1", "fixed": "9.8p1" } ]
  }
}
```

The window is **`[introduced, fixed)`**: it includes the first, excludes the
second. Several windows may be given.

> **This is an inference, not a measurement**, and the tool treats it as
> such: if the authenticated audit can read the package changelog and sees
> that the distribution backported the fix, the finding drops to
> informational. It is the difference between "this version is usually
> affected" and "this server is".

### `protocol` — by protocol version

```json
"detection": { "protocol": { "versions": ["1.99", "1.5"] } }
```

A server that answers `SSH-1.99` speaks both protocols and is exposed to
everything that is wrong with SSH-1, which no algorithm configuration fixes.

### `present` / `absent` — by algorithm

```json
{ "present": { "class": "compression", "algorithms": ["zlib"] } }
{ "present": { "class": "cipher", "tags": ["cbc"] } }
{ "absent":  { "class": "kex", "algorithms": ["kex-strict-s-v00@openssh.com"] } }
```

`class` is one of the five. It can be filtered by `algorithms` (exact names)
or by `tags`.

> **Prefer `tags`.** A rule on the `cbc` tag still holds when a CBC that does
> not exist today appears; a list of names does not.

### `host_key` — by key property

```json
{ "host_key": { "family": "dsa", "below_bits": 2048 } }
```

`family` is `rsa`, `dsa`, `ecdsa`, `ed25519`, `ed448`… and `below_bits` is
the threshold. Keys that could not be read are skipped: a key with an error
is not a 0-bit key.

### `config` — by directive

```json
{ "config": { "directive": "permitrootlogin", "equals": "yes" } }
```

Comparators: `equals`, `in`, `not_in`, `present`, `absent`. It needs
`--audit-config`; without it, the detection is left **undetermined**, which
is not the same as not being met.

### `auth_method` / `extension` — by authentication method

```json
{ "auth_method": { "methods": ["password", "keyboard-interactive"] } }
{ "extension": { "names": ["ping@openssh.com"] } }
```

`auth_method` matches if the server **offers** any of those authentication
methods; `extension`, if it advertises any of those RFC 8308 extensions. Both
need `--auth-methods`; without it, the detection is left **not determined**.

### `all`, `any`, `not` — for combining

```json
"detection": {
  "all": [
    { "absent": { "class": "kex", "algorithms": ["kex-strict-s-v00@openssh.com"] } },
    { "any": [
        { "present": { "class": "cipher", "tags": ["terrapin-vector"] } },
        { "all": [
            { "present": { "class": "cipher", "tags": ["cbc"] } },
            { "present": { "class": "mac", "tags": ["etm"] } }
        ]}
    ]}
  ]
}
```

That is the real Terrapin: **without** the countermeasure, **and** (a cipher
from the vulnerable family **or** the CBC + ETM combination). They nest
without limit.

---

## The three ways they are detected

The 65 entries are detected by one of three paths, and the difference matters for
reading the report:

- **On the wire (10).** What the server actually offers is observed, so there is
  no margin of error: Terrapin (`CVE-2023-48795`, non-strict KEX with a vulnerable
  cipher), CBC (`CVE-2008-5161`), Sweet32 (`CVE-2016-2183`, 64-bit block), LOGJAM
  (1024-bit DH or small DSA), RC4-BIAS (`arcfour*`), SHA1-SIGNATURE
  (`ssh-rsa`/`ssh-dss` host key), SSH1-PROTOCOL (`SSH-1.x` banner),
  PREAUTH-COMPRESSION (bare `zlib`), NULL-CIPHER and NULL-MAC (`none`).
- **By version (54).** The rest is inferred from the banner. These **always**
  carry the warning that distributions backport patches without changing the
  number, so they must be checked against the package *changelog*.
- **Configuration-conditioned (4).** They only apply if a non-default option is
  on: `CVE-2026-60000` (GSSAPI DoS) requires `GSSAPIAuthentication yes`, and
  knowing that requires `--audit-config`.

> **Not looking is not the same as looking and finding nothing.** A rule that
> needs data the scan did not collect is not silently evaluated to `false`: it is
> marked *not determined* and the report says which option would resolve it.
> Reporting a server as unaffected because nobody asked the question is the one
> failure mode this module cannot have.

---

## Pre-authentication compression

It is the most-asked classification, because the guides contradict each other.
What the sources say:

| Method | Classification | Why |
|---|---|---|
| `none` | Recommended | Avoids the side channel entirely |
| `zlib@openssh.com` | Recommended | Only starts **after** authenticating |
| `zlib` | **Insecure** | Starts as soon as key exchange ends |

`zlib` starts compressing — and **decompressing** — as soon as key exchange ends,
that is before anyone has authenticated, in a process that has not yet dropped
privileges. `zlib@openssh.com` does the same but waits. And it is not theoretical:

- **DISA STIG V-258002** requires it: *"the SSH daemon must not allow compression,
  or must only allow it after successful authentication"*, because a flaw in the
  compression code would be reachable *from an unauthenticated connection,
  potentially with root privileges*.
- **CVE-2026-23943** (CVSS 6.9) is exactly that: a server advertising legacy
  `zlib` that inflates client data before authenticating with no size limit.
  256 KB on the wire become about 255 MB in memory — a 1029:1 amplification — and
  exhaust the server's memory with no credentials.
- **OpenSSH removed pre-authentication compression in 7.4** (2016). Since then
  `Compression yes` means *delayed*: a modern OpenSSH **never** offers bare
  `zlib`. If you see it, it is something older or another implementation.

**And `zlib@openssh.com`?** The OpenSSH manual advises against compression *on
connections that mix trusted and untrusted data*, because the compressed length
can leak something of the secret — the shape of the CRIME attack against TLS. It
is a **conditional** risk, and that is why it stays recommended and not
*acceptable*: downgrading it would cost 2.5 points to **any** default OpenSSH, and
since A+ requires 100, none could ever score A+. The warning is in the algorithm's
notes (`--notes`), where whoever forwards other people's data will find it.

**What the standards *do not* say.** ANSSI's technical note on the secure use of
(Open)SSH **does not mention compression** —verified against the document—, and
neither BSI TR-02102-4 nor the ENS touch it. The only normative requirement that
exists is the STIG's, and it **allows** delayed compression.

Every report carries a **Compression** line in each server's header, with one of
four states: `disabled (no compression offered)`, `enabled, after authentication
only`, `enabled BEFORE authentication` (in red, with the reason) or `unknown`. In
the machine formats it is the `compression` field (JSON, CSV) and the OpenMetrics
gauge `ssh_target_compression_preauth`. And you cannot score well with `zlib` on:
it is classified `insecure`, and the `any_insecure_algorithm` cap forces the grade
to **F** no matter how good everything else is (90/100 and still an F) — which is
what happens to the lab's Dropbear.

---

## Verification against the primary sources

The version ranges do not come from memory: they were checked against
[openssh.com/security.html](https://www.openssh.com/security.html), OpenSSH's
release notes and the *Debian Security Tracker* records for openssh, dropbear and
libssh. A wrong range is worse than checking nothing, because it gives a confident
wrong answer. Two consequences:

- **`CVE-2016-20012`** is **disputed** by the OpenSSH project itself, which
  considers it inherent to the public-key method. It is included because the CVE
  record exists and some audits ask about it, but the description says it is
  disputed.
- **A freshly installed OpenSSH 10.3 comes out with three advisories**, because
  10.4 fixed things. That is correct: the grade is still A+ (the algorithms are
  impeccable) and version advisories do not score, but the report does not hide
  that there are pending patches.

Two compatibility notes. Detection is **validated on load**, not on evaluation: a
malformed condition gives an error with the vulnerability's id, instead of a rule
that never matches and nobody notices; and if a rule turns out malformed at
runtime, it is emitted as an informational finding rather than failing silently
toward "not vulnerable". There was a `flags` field that triggered a −20 modifier
and a grade cap for a single CVE; when that hook was removed it kept printing for
**one** of the 65 entries and no other, so it was deleted: how much a vulnerability
weighs is decided by its severity, like the other 64. Old `software_advisories`
entries are still accepted and converted into by-version vulnerabilities, so a
policy written earlier keeps working.

---

## Writing a new one, step by step

1. **Find the reference first.** The CVE, the advisory, the commit. If you
   cannot find it, do not write it.
2. **Decide what actually detects it.** Is it a version window? Is it an
   offered algorithm? Are both needed? Write the narrowest condition that is
   correct: a detection that fires too eagerly ends up ignored, and then the
   one that matters gets ignored too.
3. **Write `remediation` as an order.** "Upgrade to 9.8p1 or remove the CBC
   ciphers from the Ciphers directive", not "consider upgrading".
4. **Test it against the lab**, which has servers with these defects on
   purpose:

```bash
ssh-crypto-checker --config mi-politica.json --list-vulnerabilities | grep MI-ID
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2204 --no-color   # CBC sin contramedida
```

5. **Also check that it does NOT fire where it should not.** A modern server
   must not start showing your finding:

```bash
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --no-color   # modern
```

---

## The three mistakes people make

**Detecting by name what should be detected by property.** If you write out
the list of the six CBC ciphers you know today, your rule ages. Use `tags`.

**Asserting as measured what was only deduced.** A version-based detection
says that that version is usually affected. If the changelog mechanism can
refute it, let it do so: do not turn it into `critical` with a condition that
does not look at the server.

**Forgetting the remediation.** A report with twenty findings and no
instructions changes nothing on any server.
