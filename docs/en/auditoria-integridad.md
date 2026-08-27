# Integrity audit — does everything the tool asserts come from a document?

**Date:** 2026-08-13 · **Scope:** the whole project (25 profiles + base policy
`algorithms.json`: categories, strengths, vulnerabilities, configuration
checks, and scoring).

**The question it answers:** does the tool say something is "good" or "bad"
without a document backing it? In other words, have we made anything up?

## Method

Three independent verifications run in parallel, each returning **evidence**
(the line of the document where the datum appears, or "not found"), not a
sign-off:

1. **15 DISA STIG profiles** against the cited CIS/STIG benchmarks.
2. **10 non-STIG profiles** against their documents (NIST, BSI, ANSSI, ENS,
   CNSA, CIS, ISO, PCI).
3. **Base policy** `algorithms.json` against the documents present in
   `docs/estandares/`.

Plus checks of our own on the strength table, the vulnerabilities, and the
configuration checks.

## The verdict in one sentence

**There are no invented lists.** Every profile traces to its document. **A
single behavioral error** was found (the ENS profile, already fixed). The real
problem is not that the tool lies, but that **part of its judgements — correct
ones — rests on documents that are not archived in the repo**, so today they
are not *auditable* with the material at hand. And the **scoring** is our own
methodology, which should be declared as such.

---

## 1. Profiles (25) — they trace to their document

### DISA STIG (15/15) — VERIFIED, zero discrepancies
All lists come from the **Audit/Remediation** block of the cited rule (not
from the "Default Value", which is an example), no algorithm in the JSON is
missing from the document or vice versa, and every rule ID exists. Covers:
RHEL 8/9/10, AlmaLinux 9, Amazon Linux 2023, Oracle Linux 7/8, SUSE 15,
Ubuntu 20.04/22.04/24.04, Solaris 11, VMware ESXi 8.0, VMware Photon OS 4.0,
macOS 15.

- Citation nuance (not a fault): in Solaris, the cited `V-216173` is the GROUP
  ID of the **X86** edition; SPARC uses `V-216410` with the same rule and list.

### Non-STIG (9 verified + 1 fixed)
`nist-sp-800-131a`, `fips-140-3`, `cnsa-1.0`, `cnsa-2.0`, `bsi-tr-02102-4`,
`cis-benchmark-ssh`, `iso-27001-a-8-24`, `pci-dss-4` → **VERIFIED** against
the cited tables/sections of their documents.

**`ens` → ERROR FOUND AND FIXED.** The profile omitted
`diffie-hellman-group15-sha512` from its kex list, even though table 4-4 of
CCN-STIC-807 marks it **Recommended (R), 128 bits** (RFC 8268, MODP 3072) — it
meets the profile's own 128-bit minimum. Worse: the justification text
misdescribed the document ("exactly these six… group14 and below are not
there"), when the table has **seven** R rows and the missing one was group15.
The tool was **incorrectly failing** a server that ENS does allow. Fixed:
`diffie-hellman-group15-sha512` added and the justification rewritten.
Verified against the document (`pdftotext -layout`: row
"group15-sha512 … 128 R").

### Document gaps in profiles — ✅ CLOSED
The three documents a profile invoked without archiving **have now been
brought in** (freely downloadable, with their fingerprint in
`estandares/README.md`):
- **`fips-140-3`**: the ML-KEM entries now have their source, **FIPS 203**
  (`NIST.FIPS.203.pdf`). (`SP 800-140Cr2` delegates its master list to a CMVP
  URL, so FIPS 203 is the document that makes "ML-KEM approved" auditable.)
- **`anssi-rgs`**: **DAT-NT-007** (`anssi-dat-nt-007-openssh.pdf`) backs the
  exclusion of CBC — its **rule R15** mandates "AES en mode CTR" — and the
  retirement of DSA; **ANSSI-FT-116** (`anssi-ft-116-transition-pq-sshv2.pdf`,
  §3.2) backs rejecting standalone ML-KEM in favor of hybridization. Verified
  against both PDFs.

---

## 2. Base policy `algorithms.json`

### What is well anchored
- **kex and host_key**: their categories are surprisingly well backed by
  RFC 9142 + NIST SP 800-131A + FIPS 186-5 + BSI TR-02102-4 + CNSA (all
  present).
- **Strength table** (`security_strength.modulus_strength`): matches
  NIST SP 800-57 Part 1 Rev.5 **Table 2** exactly (`[15360,256] [7680,192]
  [3072,128] [2048,112] [1024,80]`), verified in the PDF.

### The real gap: cipher and mac (correct judgements, but not auditable here)
Almost everything *weak/insecure* in **cipher and MAC** rests on facts whose
**primary document is not archived** in the repo. The verdicts are correct;
what is missing is the source that vouches for them locally:

| Fact invoked | Affects | Document that would be missing |
|---|---|---|
| RC4 broken (keystream bias) | `arcfour`, `arcfour128`, `arcfour256`, pattern `arcfour*`, vuln `RC4-BIAS` | **RFC 7465** (+ rc4nomore) |
| MD5 broken | `hmac-md5*` (4) + pattern `*-md5*` | **RFC 6151** |
| Sweet32 (64-bit block) | `blowfish-*`, `cast128-*`, `idea-cbc`, vuln `CVE-2016-2183` | **CVE-2016-2183** / Sweet32 paper |
| Plaintext recovery in SSH CBC | `aes*-cbc`, `twofish*-cbc`, `serpent256-cbc`, `rijndael-cbc@…`, pattern `*-cbc*`, vuln `CVE-2008-5161` | **CVE-2008-5161 / CERT VU#958563** |
| Terrapin | tag `terrapin-vector`, vuln `CVE-2023-48795` | **CVE-2023-48795** / Terrapin paper |
| Logjam (precomputation) | escalation of `group1-sha1` to insecure, vuln `LOGJAM` | **CVE-2015-4000** / weakdh.org |
| Practical SHA-1 collisions | *rationale* of `ssh-rsa`/`ssh-dss` (the insecure **category** itself is backed by SP 800-131A + RFC 9142) | **SHATTERED** |

> Note: 3DES (`3des-cbc`/`3des-ctr`) **is** backed: NIST SP 800-131A bans
> 3TDEA after 2023 (document present). And CIS/STIG recommend `Ciphers` lists
> without CBC, partial configuration backing.

### Vulnerabilities (65) — settled by owner decision
- **3 backed by a document in the repo**: `NULL-CIPHER` and `NULL-MAC`
  (RFC 4253 §6.3/§6.4), `PREAUTH-COMPRESSION` (DISA STIG V-258002, in the
  RHEL 9 STIG).
- **62 name their CVE**: the CVE is a **publicly verifiable reference**
  (NVD/MITRE). Owner decision (2026-08-13): **CVEs are not archived** — they
  are public — citing them is enough. This is not a gap: it is the provenance
  policy for public references.

### Configuration checks (26) — ✅ FIXED
Previously, 23 of 26 did not cite their source. Now **every check carries a
`reference` field**, and a test (`test_every_config_check_cites_a_source`)
demands it:
- **Server (16)**: each cites its verified CIS/STIG rule (e.g.
  `PermitRootLogin` → CIS "Ensure sshd PermitRootLogin is disabled", RHEL 9
  v2.0.0 rule 5.1.20; X11/agent forwarding → 5.1.10 DisableForwarding; etc.).
- **Client (10)**: `StrictHostKeyChecking`, `ForwardAgent`, `HashKnownHosts`…
  are **not** in the repo's server CIS/STIGs; their normative source is the
  OpenSSH **`ssh_config(5)`** manual (a public reference, same criterion as
  the CVEs: cited, not archived).

### The tool's own methodology — ✅ DECLARED
It comes from no document — and it should not; it is a legitimate design
choice. It used to be undeclared; now it **is**: the `categories` and
`scoring` blocks of the policy file carry a `_comment` that says explicitly
that the numbers are our own judgement (not an external document's), and
[`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) opens with a
section "Where these numbers come from (and where they do not)" that
separates it from the documentary backing of the categories. It covers:
- `scoring`: per-class weights (25/25/20/20/10), modifiers, grade thresholds
  (A+…F), and caps (`grade_caps`).
- `categories`: the 100/75/35/0 `score` values and the severities.
- `security_strength.levels`: the bit **thresholds** are indeed NIST's, but
  the **names** (high/moderate/legacy/inadequate) and the "required by
  CNSA 2.0" are our own framing.
- "Opinion" categories stricter than the document: `chacha20-poly1305@openssh.com`
  as *recommended* (BSI TR-02102-4 does not mention it — 0 occurrences), the
  **UMAC** family, `hmac-ripemd160*`, the MACs truncated to 96 bits,
  `rsa2048-sha256` downgraded to *weak* for lacking forward secrecy, and the
  pre-standard sntrup/Kyber entries (no document in the repo covers them).

---

## 3. Actions — status

**Done in this audit:**
- [x] **ENS error fixed** (`diffie-hellman-group15-sha512`), verified against
  the document.
- [x] **All 26 config checks cite their source** (`reference` field; server →
  CIS/STIG rule, client → `ssh_config(5)`), with a test that demands it.
- [x] **Scoring is declared as our own methodology** (`_comment` in
  `categories`/`scoring` + new section in `como-se-calcula-la-nota.md`).
- [x] **CVEs**: owner decision — they are public, they are cited and **not
  archived**. Likewise for the client-side OpenSSH manuals.
- [x] **Missing documents, now brought in**: FIPS 203 (`NIST.FIPS.203.pdf`),
  ANSSI DAT-NT-007 and ANSSI-FT-116 are archived in `estandares/`, so
  `fips-140-3` and `anssi-rgs` are audited against the source.

**On cipher/mac (category B):** the verdicts are correct and rest on
**public** references (RFC 7465/RC4, RFC 6151/MD5, and the CVEs for Sweet32,
Logjam, Terrapin, CBC/SSH, SHA-1/SHATTERED). Under the same policy as the
CVEs, those public references **are cited, not archived**. Every algorithm
note names them; there is no verdict without a public reference behind it.

**Optional, pending:** refine the Solaris citation (name the SPARC edition
`V-216410`).

---

## Conclusion

The tool **makes nothing up**: the 25 profiles trace to their document, the
only real error (ENS) is fixed, and every judgement in the base policy has
behind it **either a document we hold, or a publicly verifiable reference**
(CVE, RFC, OpenSSH manual) that — by provenance decision — is cited but not
archived. The scoring methodology, which is our own judgement, is declared as
such. The three documents that were missing (FIPS 203, DAT-NT-007,
ANSSI-FT-116) are now archived in `estandares/`, so `fips-140-3` and
`anssi-rgs` are audited against the source and not from memory.
