# How the grade is calculated

This document is **the complete, public scoring system**. Nothing is hidden:
every number comes from the policy file, which can be read, exported, and
changed.

If what you want is to **change** those numbers, go to
[`politica-puntuacion.md`](politica-puntuacion.md). This explains **how it
works** and **why**, which is what someone needs when a C has just landed on
them and they want to know whether it is fair.

## Where these numbers come from (and where they do not)

Two things are worth separating, because they have different origins:

- **Which algorithms are good or bad** — that `aes256-cbc` is *weak* or that
  `chacha20-poly1305@openssh.com` is *recommended* — **comes from documents**: a
  standard that retires an algorithm, an RFC, a published break. Each algorithm
  says so in its note, and the [integrity audit](auditoria-integridad.md)
  traces which document each judgement comes from.
- **How those judgements become a letter** — the per-class weights
  (25/25/20/20/10), the point modifiers, the grade thresholds (A+…F) and the
  caps — **is this tool's own judgement**, not taken from any external
  document. It is a methodology: legitimate, but a **choice**. That is why it
  is written out in full here and justified number by number, so it can be
  debated or changed, not mistaken for a documented requirement. In the
  policy file, the `categories` and `scoring` blocks declare it as such in
  their `_comment`.

The only scoring figure that **does** come from a document is the **strength
bands in bits** (192/128/112): they are those of NIST SP 800-57 Part 1 Rev. 5,
Table 2. The **names** of those bands (high/moderate/legacy) are our own
presentation.

---

## Two answers, not one

The tool gives **two different things** about each server, and it pays not to
confuse them:

| | What it is | What it is for |
|---|---|---|
| **The grade** (`A+` … `F`) | A number compressed into a letter. | Comparing, tracking over time, putting on a dashboard. |
| **The verdict** (`secure`, `acceptable`, `weak`, `insecure`) | A judgement about the state. | Deciding whether action is needed. |

They are computed along different paths on purpose: **a high average does not
erase a broken thing**. But they cannot contradict each other, and that is
the only rule tying the two halves together:

> **No server with a `weak` verdict can have a grade better than `C`, and
> none with an `insecure` verdict can have better than `F`.**

It is checked against the 96 lab servers on every run of the suite, not
against the four cases somebody happened to think of.

### The verdict table

| Verdict | When |
|---|---|
| `secure` | Everything recommended and with strict KEX. |
| `acceptable` | Nothing weak or insecure, but something could be better. |
| `weak` | Some weak algorithm, short key material, **or some confirmed critical or high vulnerability**. |
| `insecure` | Some insecure algorithm. |
| `unknown` | The server was reached but the policy recognises **nothing** it offers. |
| `error` | It could not be scanned. |

On `unknown`: if the policy classifies none of the server's algorithms, the tool
**does not invent a grade**. It returns `score` and `grade` as `null`, marks the
verdict `unknown` and emits a finding naming which classes went unassessed. An
`F` would suggest the server is insecure and an `A` that it is fine; neither is
backed by the evidence. If only some classes go unclassified it is still scored
-- the weights redistribute across the assessable ones -- but the finding warns
that the grade is partial.

That the verdict is **independent of the grade** mattered because of Terrapin: it
was the one vulnerability the verdict looked at, named in the code and nowhere
else, so a server with a confirmed critical CVE summed up as `secure` while the
page below said otherwise. Terrapin is a high-severity match; now **all weigh
equally**, which is what that was a special case of.

---

## The five steps

### 1. Every algorithm gets a category

From the lists in the policy file. Each category is worth points:

| Category | Points |
|---|---|
| `recommended` | 100 |
| `acceptable` | 75 |
| `weak` | 35 |
| `insecure` | 0 |
| `informational` | *not scored* |
| `unknown` | *not scored* |

**`unknown` does not penalize**, and that is deliberate: servers are forever
offering names nobody has catalogued, and punishing them would treat someone
using something new and good the same as someone using something odd and bad.
It appears in the report as "unclassified" so that someone takes a look.

### 2. Each class is scored by **its worst algorithm**

```
class score = minimum of the scores of what it offers
```

It is not the average, and this is what surprises people most. The reason is
the protocol itself: **the client is the one that chooses the algorithm**,
from among those the server offers. A server with twelve excellent ciphers
and one broken one can be steered onto the broken one by any misconfigured
client — or by whoever sits in the middle. To offer it is to allow it.

The five classes are key exchange (`kex`), host key (`host_key`), cipher
(`cipher`), MAC (`mac`), and compression (`compression`).

### 3. The classes are combined with their weights

| Class | Weight |
|---|---|
| `kex` | 25 |
| `host_key` | 25 |
| `cipher` | 20 |
| `mac` | 20 |
| `compression` | 10 |

```
base = Σ (class score × weight) / Σ weights
```

Key exchange and the host key weigh more than the cipher because they are
what decides whether the session can be **impersonated** or **decrypted
later** — including decrypting it ten years from now from what gets recorded
today — while the cipher only decides how hard it is to read it live.
Compression weighs little because it is almost never enabled and its problem
is bounded.

A class that could not be scored (everything unknown) stays out of the
average: it neither adds nor subtracts, and its weight drops out of the
divisor.

### 4. The modifiers add or subtract

Facts that are not an algorithm on a list:

| Modifier | Points | Why |
|---|---|---|
| `missing_strict_kex` | −10 | Without strict key exchange the handshake transcript is not authenticated, and messages can be removed from it without either end noticing. |
| `no_post_quantum_kex` | −5 | No hybrid post-quantum key exchange: exposure to "record now, decrypt later". |
| `host_key_below_minimum` | −25 | A host key below the minimum. |
| `host_key_below_recommended` | −5 | Below the recommended size. |
| `dh_group_below_minimum` | −15 | The negotiated Diffie-Hellman group is smaller than the minimum. |

**No specific vulnerability appears in this table, and that is deliberate.**
There was once a `terrapin_vulnerable` modifier of −20: one CVE that moved
the number because it had its name in the code, while the other 64 moved
nothing. What a server loses for a vulnerability is decided by the caps,
according to its **severity**. What does stay here is the lack of strict key
exchange, which is a property of the negotiation — like not offering
post-quantum — not a CVE.

The result is clamped to `[0, 100]`.

> A vulnerability detected **by version** does not move the number
> (`version_advisories_affect_score: false`). An inference from a version
> string should not change a grade. For the serious cases there are the caps,
> which are the next step.

### 5. The number becomes a letter, and then the caps come down

| Grade | From | Also requires |
|---|---|---|
| `A+` | 100 | strict key exchange, post-quantum, and correct host keys |
| `A` | 90 | |
| `B` | 80 | |
| `C` | 65 | |
| `D` | 50 | |
| `F` | 0 | |

And then, **the caps**: conditions that put a ceiling on the grade no matter
what happens with the number.

| If… | The grade cannot exceed |
|---|---|
| Something `insecure` is offered | `F` |
| Something `weak` is offered | `C` |
| A host key falls below the minimum | `D` |
| There is a confirmed **high or critical** vulnerability | `C` |
| There is a **measured** critical one (not deduced from the version) | `F` |
| There is a critical one the package changelog did **not** refute | `F` |

The caps exist because **an average lies**. A server with twenty excellent
algorithms and one broken one has a very good average and a very serious
problem.

---

## The three answers to a CVE

The last three caps in the table are the same issue seen at three degrees of
certainty, and they deserve an explanation because this is where the system
is at its most precise:

| What is known | Maximum grade | Why |
|---|---|---|
| The advertised version matches a high or critical CVE, and nobody has been able to look at the package | **C** | It is an open question. Distributions patch without changing the version number, so it is not an accusation — but it is not an `A` either. |
| The package changelog could be read and it **mentions** the fix | *no cap* | The distribution says it fixed it. The finding drops to informational, with the changelog line quoted. |
| The changelog could be read and it does **not** mention it | **F** | It is no longer an inference: the package does not claim to have fixed it. |

A design detail the lab corrected along the way: there was an eighth cap,
`any_critical_vulnerability` with a ceiling of `C`, and **it was redundant**.
Every critical also counts as high, and the cap for highs was already at `C`,
so it could never bite on its own. The suite caught it because it checks that
**every cap that can bite is seen biting** on some lab server: a limit that
never fires is a decorative limit.

This is the same thing the tool does with compliance standards, where there
are three answers, not two: compliant, non-compliant, and **not assessed**.
"I don't know" is an answer in its own right, and saying `A` in its place is
exactly how a security tool deceives those who trust it.

> **This changed.** Until August 2026, a vulnerability detected by version
> set no ceiling unless the changelog had been read. The result was that a
> Debian 11 with a confirmed critical CVE got an **`A`** while its own
> verdict said `weak`: two mechanisms, the same evidence, opposite
> conclusions. In the lab this happened to 4 out of 96 servers.

---

## A complete example, actually calculated

A server without strict key exchange and with a CBC cipher among those it
offers:

```
clases:  kex 100   host_key 100   cipher 35   mac 100   compression 100
pesos:   kex  25   host_key  25   cipher 20   mac  20   compression  10

base = (100×25 + 100×25 + 35×20 + 100×20 + 100×10) / 100 = 87

modificadores:
  missing_strict_kex    -10
  no_post_quantum_kex    -5
                       ----
final = 87 - 15 = 72

72 sits in the C band (≥ 65)
topes: ofrecer algo 'weak' pone el techo en C, que es donde ya estaba
nota: C          veredicto: weak
```

This example was worth 52 and a D when a `terrapin_vulnerable` modifier of
−20 existed. With it removed, the same server rises to 72 and a C, and the
grade stops depending on which vulnerability had its own name in the code.
What still keeps it from going above C is the CBC cipher, which is a measured
property of the server.

Notice that **the CBC cipher is worth 35 and drags its entire class down to
35**, even though the server also offers three perfect ciphers. That is step
2, and it is the one that costs the most grade.

You can reproduce it with:

```bash
ssh-crypto-checker 127.0.0.1:2204 --format json -o informe.json
```

The `score_breakdown` object in the JSON carries the per-class scores, the
weights, the base, every modifier applied, and the final result. **There is
no arithmetic the tool does not show.**

---

## What to do if you disagree

The numbers are not sacred: they are a file.

```bash
ssh-crypto-checker --export-policy mi-politica.json
$EDITOR mi-politica.json          # scoring.class_weights, scoring.modifiers…
ssh-crypto-checker --config mi-politica.json -f inventario.txt
```

If your organization believes compression should weigh more, or that lacking
post-quantum should not cost points yet, change it and document why. The
only thing you should not do is change it halfway through a historical
series without rescanning the fleet: the grades would stop being comparable
with one another.
