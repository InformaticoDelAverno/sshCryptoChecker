# Policy manual — standards (compliance profiles)

> Before this, read [`politicas.md`](politicas.md).

A standard is written as a JSON file under
`data/profiles/<identifier>/<edition>.json`. It serves both to encode a
published standard and to write **your organization's internal policy** and
measure the fleet against it.

Beyond its own grade, each server is evaluated against these standards
**independently**, and **two different questions** are answered that are worth
not mixing up: *how strong is it?* (a NIST level) and *does it meet standard X?*
(a profile that passes or fails).

---

## The structure: one directory per standard, one file per edition

```
data/profiles/
  bsi-tr-02102-4/
    2026-01.json
  mi-empresa/
    2026.json
    2025.json
```

- **The directory is the identifier**: `--profile mi-empresa`.
- **The file is the edition**: `--profile mi-empresa@2025`.
- A bare name means **the edition currently in force**. A `name@edition` means
  that one. Two different questions — "does it pass BSI?" and "does it pass the
  edition we were audited under?" — and both get asked.
- With more than one edition, **exactly one** must carry `"current": true`.
  If none does, or several do, the loader refuses, because which one governs
  today is exactly what a compliance tool must not guess.

The file name is the selector, so it has to be typeable: lowercase, digits,
dots and hyphens. `Edición de 2025.json` is rejected.

This exists because a standard **is maintained by someone else and revised on
their schedule**: BSI publishes TR-02102-4 every January, CIS versions its
benchmarks per distribution, CNSA went from 1.0 to 2.0. Adding next year's is
adding a file; last year's stays where it is and can still be measured against.

**Three things that were deliberately *not* done:**

- **Vulnerabilities and algorithms stay in `algorithms.json`.** They are this
  tool's model, not external documents with editions. They were 69 % of the file
  before the profiles (15 %) were split out, so if the criterion were "the file
  is big" you would have started with them; the criterion is another.
- **`cis-benchmark-ssh` was not split into six.** Its edition cites six
  benchmarks (Ubuntu 22.04 and 24.04, Debian 11 and 12, RHEL 8 and 9) because
  **the six share the same body of rules**. One file per edition, not per cited
  document.
- **No historical edition was invented.** The structure allows several; encoding
  the 2024 BSI requires reading that text. Filling it in by eye would be the same
  as padding `algorithms.json` with invented vulnerabilities.

> **Two things travel together.** A policy exported with `--export-policy` takes
> its `profiles/` directory along, because a policy file with no standards
> **does not error**: it looks exactly like a scan against standards that
> everyone passes. And `pyproject.toml` declares `data/profiles/*/*.json` on top
> of `data/*.json`, because the first pattern does not reach subdirectories and a
> wheel would have shipped without them — also silently. `tests/test_packaging.py`
> requires every file under `data/` to be covered by some pattern. Exporting a
> second policy into the same directory **is allowed** (a site with a strict
> policy and a lax one shares a single set of standards); what is refused is
> overwriting a standard file that **says something else**, and the refusal
> happens *before* anything is written: half an export is worse than none.

---

## The strength levels (NIST SP 800-57)

The first question — *how strong is it?* — is answered as **effective security
strength in bits**, per **NIST SP 800-57 Part 1 Rev. 5, Table 2**. It is that of
the weakest algorithm the server accepts, because that is the one an attacker can
negotiate.

| Level | Bits | Meaning |
|---|---|---|
| **High** | ≥ 192 | Confidentiality for decades. It is what CNSA 2.0 requires. |
| **Moderate** | ≥ 128 | The general NIST and BSI target for new systems. No foreseen expiry. |
| **Legacy** | ≥ 112 | Acceptable per NIST SP 800-131A **only through the end of 2030**. Plan the migration. |
| **Inadequate** | < 112 | Forbidden by NIST SP 800-131A. |

The report also names **which concrete algorithms** are holding the level down,
so the figure is actionable:

```
Strength      128-bit — Moderate
  Effective security strength 128 bits (Moderate): ... Held down by
  mlkem768x25519-sha256 (key exchange), curve25519-sha256 (key exchange).
```

For RSA and DSA host keys the strength comes from the **actual key size**
obtained (2048→112, 3072→128, 7680→192, 15360→256 bits), not from the algorithm
name. The band names (high/moderate/legacy) are our presentation; the bit
thresholds are NIST's.

> These levels are **NIST cryptographic strength bands**. They are not the
> Low/Moderate/High impact levels of **FIPS 199**: those classify a *system* by
> the consequences of its compromise, something no network scan can determine.

---

## The two kinds

### `algorithm-strength` — the standard says which algorithms are acceptable

The normal case. Nine of the ten the tool ships with are like this.

```json
{
  "name": "Acme cryptographic policy",
  "authority": "Information Security, Acme S.A.",
  "kind": "algorithm-strength",
  "edition": "v3, approved by the 2026-02-11 committee",
  "reference": "Document SEC-014 v3, section 4.2 (SSH algorithm table).",
  "url": "https://intranet.acme.example/sec-014",
  "summary": "What Acme requires of any SSH server reachable from the corporate network.",
  "current": true,
  "minimum_security_strength": 128,
  "minimum_key_bits": { "rsa": 3072, "ecdsa": 256, "ed25519": 256 },
  "require_strict_kex": true,
  "require_post_quantum": false,
  "algorithms": {
    "kex": {
      "allow": ["curve25519-sha256", "mlkem768x25519-sha256"],
      "reason": "Modern curves and the post-quantum hybrid only."
    },
    "cipher": {
      "disallow": ["3des-cbc", "aes128-cbc", "aes256-cbc"],
      "reason": "Nothing in CBC mode."
    }
  }
}
```

| Field | Required | What it does |
|---|---|---|
| `name` | **yes** | What it is called in the report. |
| `authority` | no | Who publishes it. |
| `kind` | no (`algorithm-strength`) | The kind. |
| `edition` | no | **Set it.** A compliance claim that does not say which version it was checked against is worth nothing. |
| `reference` | no | Where the lists come from, in enough detail to verify it. |
| `url`, `summary`, `notes` | no | Context. `notes` records **where our reading extends the standard** (e.g. accepting the `@openssh.com`/`-etm` spellings when the standard only names RFC identifiers). |
| `current` | no | Whether it is the edition in force. With a single edition it is implied. |
| `minimum_security_strength` | no | Minimum effective bits. |
| `minimum_key_bits` | no | Per key family. |
| `require_strict_kex` | no | Require the server to negotiate strict key exchange. |
| `require_post_quantum` | no | Require post-quantum key exchange. |
| `algorithms` | no | Per class: `allow`, `disallow`, `disallow_unless_strict_kex` and `reason`. The lists accept wildcards. |

**`allow` and `disallow` are different ways of thinking:**

- `allow` is a **whitelist**: anything the server offers that is not on it is
  non-compliant. It is what the strict standards do (FIPS, CNSA).
- `disallow` is a **blacklist**: only what is named is non-compliant. It is
  what the CIS benchmark does.

They are not the same thing, and choosing wrong produces a standard that
passes what it should not. If your document says "only … is permitted", it is
`allow`.

`disallow_unless_strict_kex` is for what a standard excludes **only as long
as** there is no strict key exchange. The reason comes from your `reason`, and
that is what gets printed: the tool does not write a rationale for you.

### `policy-conformance` — the standard says "have a policy and comply with it"

Some standards do not list algorithms: they require the organization to define
its own. ISO/IEC 27001 A.8.24 is literally that.

```json
{
  "name": "ISO/IEC 27001:2022 A.8.24",
  "authority": "ISO/IEC",
  "kind": "policy-conformance",
  "reference": "ISO/IEC 27001:2022 Annex A control 8.24 …",
  "forbid_local_categories": ["insecure", "weak"]
}
```

Instead of a list of its own, it measures the server **against the policy
file**: `forbid_local_categories` says which local categories constitute a
violation. It is the only profile that changes meaning when you edit
`algorithms.json`, and that is exactly what the standard asks for.

#### On ISO: what can and cannot be claimed

**ISO/IEC 27001:2022 does not define cryptographic strength levels.** Its A.8.24
"Use of cryptography" control requires the organization to *define and implement*
rules for the use of cryptography, but it deliberately names no algorithms and
sets no high/medium/low levels. Neither does ISO/IEC 27002. (ISO/IEC 19790 does
have levels 1–4, but they rate the cryptographic *module* — physical resistance,
role management — not the choice of algorithms.)

That is why the tool **does not say "high level per ISO"**: it would be inventing
it. What it does is what A.8.24 actually asks: `iso-27001-a-8-24` checks the
server **against this policy file**, which *is* the documented set of rules. A
`PASS` is auditable evidence that the server applies your cryptographic policy;
it is not an ISO certification, and on its own it says nothing about strength:
read it alongside the NIST profiles.

```bash
# Evidence for A.8.24: the fleet applies the documented policy, dated and reproducible
ssh-crypto-checker -f inventario.txt --require-profile iso-27001-a-8-24 \
                   --format html,json -o evidencia-a824
```

---

## Three answers, not two

A profile can come out **not assessed**, and that is an answer in its own right:

```
[PASS] ENS (Esquema Nacional de Seguridad)  CCN (Spain)
[FAIL] CNSA 1.0 (transitional suite)        NSA
       - 128-bit effective security strength
[ ?  ] FIPS 140-3 approved algorithms       NIST
       not assessed: this profile requires host keys of a minimum size and no
       host key could be inspected
```

The rule is: **a violation is proof and overrides everything else**; finding one
settles the matter even if something else went unchecked. With no violations, it
is only a `PASS` if *all* of the profile's requirements were actually tested.

It sounds obvious and it was not. Until this version, a profile that required a
minimum key size and had been unable to inspect any key answered `PASS` with a
prose caveat; a proprietary appliance advertising names the policy does not
recognize came out **compliant with nine standards**, because the unknown was
skipped instead of judged. It is the same failure the tool warns against
elsewhere — *"a check that never ran must not be confused with one that came out
clean"* — committed by the tool itself. Now that server passes **zero**.

What can leave a profile unassessed:

| Situation | Why it is not a pass |
|---|---|
| Requires a minimum key size and none could be read | Nobody has looked at the key |
| Requires a minimum strength and the strength could not be established | Nothing to compare against |
| Requires post-quantum and the exchange could not be judged | "Unknown" is not "absent" |
| **Forbids** certain algorithms and the server offers unknown names | The vendor's name does not say what is underneath |
| Measures against your policy's categories and some algorithm has none | The question cannot be answered |

The asymmetry of the fourth case is deliberate. Against a **whitelist**, an
unknown algorithm is a demonstrable violation: not being on a closed list is
decided by the name and nothing else. Against a **blacklist** it is not: that
`vendor-cipher-a@example.com` does not appear on it does not mean it is not,
underneath, one of the forbidden ones.

In OpenMetrics these are two series, so they can be told apart when alerting:
`ssh_target_profile_conformance` (1 only if it passes) and
`ssh_target_profile_not_assessed`.

---

## Profiles are not a reflection of the tool's own grade

A server can fail the local policy and pass a standard, or the reverse. Three
real examples the tool produces:

- An OpenSSH 10 with `mlkem768x25519-sha256` and `chacha20-poly1305@openssh.com`
  scores **A+** here and **fails FIPS 140-3**: it is excellent cryptography, but
  ChaCha20-Poly1305 and X25519 are not NIST-approved.
- A FIPS server with no strict KEX and no post-quantum scores only a **C** here
  and **passes NIST, FIPS and BSI**.
- `hmac-sha1` **passes** NIST SP 800-131A — HMAC does not depend on collision
  resistance, and the standard still accepts it — even though this policy rates
  it `weak`. The profile reflects the standard, not the local opinion.

---

## Verification against the primary sources

The profiles have been checked against the published documents, not against the
memory of them. These results are worth knowing because they contradict what
almost everyone assumes (each with its verbatim quote in
`estandares/CITATION_MAP.md`):

- **BSI recommends neither `ssh-ed25519` nor any RSA key for SSH.** Table 5 of
  TR-02102-4 has three rows and the only practical entry is ECDSA over
  nistp256/384/521. It does not mention `curve25519-sha256` anywhere either.
- **ANSSI expressly recommends ChaCha20-Poly1305**, which BSI does not. Rejecting
  it "in ANSSI's name" would be false.
- **ANSSI publishes no `KexAlgorithms` or `HostKeyAlgorithms` list.** Its SSH
  note is from 2015 and covers only `Ciphers` and `MACs`. This profile encodes
  its rules by mechanism, not an invented configuration.
- **CIS works by exclusion.** An algorithm CIS does not name is compliant. Its
  audit regex is broader than the remediation string printed in the same rule,
  and excludes `umac-128-etm@openssh.com` but not `umac-128@openssh.com`. **CIS
  has no `HostKeyAlgorithms` rule.**
- **CNSA 2.0 admits no classical fallback**: *"any algorithm other than
  ML-KEM-1024 MUST NOT be negotiated"*. No current SSH meets it, and the profile
  says so: a failure measures the migration gap, not a misconfiguration. For what
  is achievable today there is `cnsa-1.0`.
- **ANSSI and NSA flatly contradict each other on post-quantum.** ANSSI requires
  hybridization; CNSA 2.0 forbids anything but ML-KEM-1024 standalone. There are
  tests that pin the contradiction so it is not "resolved" by accident.
- **`hmac-sha1` is still acceptable for NIST SP 800-131A**, because HMAC does not
  depend on collision resistance. The local policy marks it `weak`; the profile
  reflects the standard.
- **The ENS does not grade SSH algorithms by category.** CCN-STIC-807 applies the
  same R1 reinforcement in MEDIA and ALTA, and `mp.com.2`/`mp.com.3` depend on
  the **dimension level**, not the system's category. And **128 bits is the
  ceiling**: the ENS does not require AES-256 or SHA-512 even at ALTA. There is a
  single `ens` profile.
- **CCN-STIC-807 §4.2 does have SSH-specific tables**, classifying each algorithm
  as *Recommended* or *Legacy*. **The Legacy window expired on 31 December 2025**,
  so RSA host keys, group 14, CBC and `hmac-sha1` are no longer authorized. Like
  BSI, the ENS leaves **only ECDSA** as a host key: two national standards
  written separately reach the same conclusion.
- Legal correction: the cryptographic-key-protection measure of RD 311/2022 is
  **`op.exp.10`**, not `op.exp.11` — that was its code in the repealed RD 3/2010.

---

## The cryptographic inventory (PCI DSS 12.3.3)

The `pci-dss-4` profile answers "are the algorithms strong enough?". Requirement
**12.3.3**, mandatory since 31 March 2025, asks a different thing: a **documented
inventory** of the cryptographic suites and protocols in use, reviewed at least
once a year, with tracking of the algorithms that are losing validity and a
written strategy to replace them.

`--format inventory` produces that document in Markdown:

```bash
ssh-crypto-checker -f inventario.txt --format inventory -o inventario-cripto.md
```

It contains the in-scope systems with their implementation, the **excluded** ones
and why — a server that could not be scanned is a gap in the evidence and says
so — each algorithm **once** with the servers that offer it and its standing
under the policy, the ones to retire with the reason, the post-quantum posture
and the response strategy.

No judgement in the document is decided in code: they all come from the policy
file. An inventory generated today and one after the next policy update differ
exactly on what the industry has changed its mind about, which is the review the
requirement actually asks for.

---

## Writing your own, step by step

1. **Create the directory** with the identifier people are going to type:
   `data/profiles/mi-empresa/` — or next to your exported policy, if you work
   with `--export-policy`.
2. **Create the edition file**: `2026.json`.
3. **Fill in `reference`** with the actual document and section. Two years
   from now someone will ask where each line came from.
4. **Choose `allow` or `disallow`** according to what your document says.
5. Check it:

```bash
ssh-crypto-checker --config mi-politica.json --list-profiles
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --profile mi-empresa --no-color
```

6. And so that a scan **fails** when someone does not comply:

```bash
ssh-crypto-checker -f inventario.txt --require-profile mi-empresa --fail-on high
```

`--profile` and `--require-profile` do different things and **can be combined**:
`--profile` *filters the report* (shows only those profiles); `--require-profile`
is *a gate* (exits with **code 1** if any server does not comply, to block a CI
deployment). Both are independent of `--fail-on <severity>`, which is the gate
for **vulnerabilities/findings**, not for conformance.

A test checks that no whitelist mentions algorithms the policy does not know, so
that a typo cannot silently fail every server. `kind: "policy-conformance"` +
`forbid_local_categories` makes a profile measured against the categories of this
same file, like the ISO one.

---

## Two warnings

**Profiles are for triage; they do not replace an auditor.** Several standards
require things no network scan can see: the ENS at category MEDIA and ALTA
requires **certified products from the CPSTIC catalogue** (CCN-STIC-105), and
FIPS 140-3 requires a **validated module**, not just approved algorithms. A
`PASS` here is a necessary condition, not a sufficient one.

**Do not invent the contents of an edition you have not read.** The structure
supports multiple editions; encoding the 2024 BSI requires reading that text.
Filling it in by eye produces a false compliance report, which is worse than
having none.
