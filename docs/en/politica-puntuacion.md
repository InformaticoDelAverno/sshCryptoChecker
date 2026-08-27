# Policy manual — scoring, grades, and caps

> Before this, read [`politicas.md`](politicas.md).

This is where **the grade a server gets** is decided. It is the part of the
file with the most consequences: changing one weight changes every report.

---

## How the grade is calculated, in order

1. **Each algorithm class earns a score** from the categories of what the
   server offers.
2. **The scores are combined using the weights** in `class_weights`.
3. **The modifiers are applied**, adding or subtracting points for facts that
   are not an algorithm.
4. **The resulting number becomes a grade** using the `grades` scale.
5. **The caps are applied**: a `grade_caps` condition can lower the grade
   however much the number says otherwise.

The verdict (`secure`, `acceptable`, `weak`, `insecure`) is decided **separately**
from the number. A server can score a good number and still get a bad verdict:
that is deliberate, because a high average does not erase a broken thing.

---

## The weights

```json
"class_weights": { "kex": 25, "host_key": 25, "cipher": 20, "mac": 20, "compression": 10 }
```

They do not have to add up to 100; they are normalized. What this table says
is what matters most: here, key exchange and the host key are each worth more
than the cipher, because they are what decides whether the session can be
impersonated or decrypted later.

---

## The modifiers

Points added or subtracted for facts that do not come from the algorithm
lists:

```json
"modifiers": [
  { "id": "missing_strict_kex",         "points": -10, "description": "..." },
  { "id": "no_post_quantum_kex",        "points":  -5, "description": "..." },
  { "id": "host_key_below_minimum",     "points": -25, "description": "..." },
  { "id": "host_key_below_recommended", "points":  -5, "description": "..." },
  { "id": "dh_group_below_minimum",     "points": -15, "description": "..." }
]
```

The `id` values are the ones the tool knows how to compute; an invented one
does nothing. What you can change freely is **how many points** each one is
worth, which is where the judgement lives.

`"version_advisories_affect_score": false` says that a vulnerability detected
**by version** does not move the number. It is the prudent stance: an
inference from a version number should not change a grade, and for the
serious cases there are already the caps.

---

## The grade scale

```json
"grades": [
  { "grade": "A+", "min_score": 100, "requires": ["strict_kex", "post_quantum", "host_keys_ok"] },
  { "grade": "A",  "min_score": 90 },
  { "grade": "B",  "min_score": 80 },
  { "grade": "C",  "min_score": 65 },
  { "grade": "D",  "min_score": 50 },
  { "grade": "F",  "min_score": 0 }
]
```

It is walked from top to bottom and the first entry whose `min_score` is
reached wins. `requires` adds conditions that must **also** be met: here, an
A+ demands strict key exchange, post-quantum key exchange, and correct host
keys, however high the number is.

The list **cannot be empty**: without a scale there is no grade, and the
loader rejects it.

---

## The grade caps

A cap says: **whatever happens with the number, the grade cannot rise above
this point.**

```json
"grade_caps": [
  { "when": "any_insecure_algorithm", "max_grade": "F" },
  { "when": "any_weak_algorithm",     "max_grade": "C" },
  { "when": "any_high_vulnerability", "max_grade": "C" },
  { "when": "host_key_below_minimum", "max_grade": "D" },
  { "when": "any_measured_critical_vulnerability", "max_grade": "F" },
  { "when": "any_critical_vulnerability_the_changelog_did_not_clear", "max_grade": "F" }
]
```

They exist because an average lies. A server with twenty excellent algorithms
and one broken one has a very good average and a very serious problem. The
cap cuts through that arithmetic.

### The conditions that can be used

| `when` | It holds when |
|---|---|
| `any_insecure_algorithm` | Something in category `insecure` is offered. |
| `any_weak_algorithm` | Something in category `weak` is offered. |
| `host_key_below_minimum` | A host key falls below the minimum. |
| `any_critical_vulnerability` | Any critical vulnerability, including those inferred from the version. |
| `any_high_vulnerability` | The same, at high severity. |
| `any_measured_critical_vulnerability` | A critical one **measured on the server**, not deduced from a version number. |
| `any_critical_vulnerability_the_changelog_did_not_clear` | A critical one the changelog audit did **not** refute. A server patched by its distribution is not punished. |

> **A `when` that does not exist is rejected at load time**, along with the
> list of valid ones. A cap that never fires because of a typo is worse than
> not having one: you look protected and you are not.

The last two conditions are the ones worth understanding. `any_critical_vulnerability`
punishes a server whose distribution already backported the fix; the other
two do not. Choose according to what you want: maximum rigor or precision.

---

## Effective security strength

Besides the grade, the tool reports **how many effective bits of security**
the connection has: the weakest link in the chain.

```json
"security_strength": {
  "reference": "NIST SP 800-57 Part 1 Rev. 5",
  "url": "https://doi.org/10.6028/NIST.SP.800-57pt1r5",
  "modulus_strength": [ [15360, 256], [7680, 192], [3072, 128], [2048, 112] ],
  "levels": [
    { "id": "high",     "minimum_bits": 192, "label": "High",     "description": "..." },
    { "id": "moderate", "minimum_bits": 128, "label": "Moderate", "description": "..." }
  ]
}
```

- **`modulus_strength`** translates the size of an RSA or Diffie-Hellman
  modulus into bits of security. They are `[modulus_bits, security_bits]`
  pairs, and the largest one that does not exceed the observed size applies.
- **`levels`** are the bands the result is labeled with. They sort themselves
  by `minimum_bits`.

The per-algorithm bits come from `security_strength_bits` in each entry,
which is documented in [`politica-algoritmos.md`](politica-algoritmos.md).

---

## Before you touch any of this

Changing the weights or the caps changes **every** report you produce, and
the historical ones will stop being comparable. If you maintain a time
series:

1. Change the policy.
2. Rescan the entire fleet with the new policy.
3. Start the series from there, and write down why.

And check it against the lab, which has servers on every rung of the ladder:

```bash
for puerto in 2222 2223 2224 2225; do
  ssh-crypto-checker --config mi-politica.json 127.0.0.1:$puerto -q --no-color | head -3
done
```
