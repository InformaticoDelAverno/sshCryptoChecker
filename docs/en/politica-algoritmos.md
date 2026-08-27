# Policy manual — algorithms

> Before this, read [`politicas.md`](politicas.md).

This is the part of the policy that decides **what the tool thinks of each
algorithm a server offers**. It is the part that gets edited most and the one
that ages fastest.

---

## The six categories

They are defined in the `categories` key. Each one has a label, an
abbreviation, a **score** and a **severity**:

| Category | Points | Severity | What it means |
|---|---|---|---|
| `recommended` | 100 | info | Modern, with no known practical weakness. |
| `acceptable` | 75 | low | It works, but there is something better. |
| `weak` | 35 | medium | Known weakness; it has to go. |
| `insecure` | 0 | critical | Broken. Nothing should offer it. |
| `informational` | *(no points)* | info | Reported, not scored. For what is neither good nor bad. |
| `unknown` | *(no points)* | info | The policy does not know it. **Not scored, on purpose.** |

```json
"categories": {
  "weak": {
    "label": "Weak",
    "short": "WEAK",
    "score": 35,
    "severity": "medium",
    "description": "Known weakness. Remove it when you can."
  }
}
```

> **`unknown` does not penalize, and that is deliberate.** Servers offer names
> nobody has catalogued all the time. Lowering the grade for an algorithm the
> policy does not know punishes whoever uses something new and good exactly
> the same as whoever uses something odd and bad.

You can add categories of your own. All they need is a
`label` and a `severity`; without a `score`, they do not score.

---

## The five classes

`algorithms` has exactly five keys, and **all five are mandatory**:

| Class | `sshd_config` directive |
|---|---|
| `kex` | `KexAlgorithms` |
| `host_key` | `HostKeyAlgorithms` |
| `cipher` | `Ciphers` |
| `mac` | `MACs` |
| `compression` | `Compression` |

Deleting one does not mean "this class doesn't matter to me": it means a
server could offer anything there without anyone saying a word. The loader
rejects it.

Each class is written like this:

```json
"cipher": {
  "label": "Cipher",
  "sshd_config_directive": "Ciphers",
  "entries": { ... },
  "patterns": [ ... ]
}
```

---

## The entries: one algorithm, one opinion

```json
"entries": {
  "aes256-gcm@openssh.com": {
    "category": "recommended",
    "security_strength_bits": 256,
    "tags": ["aead"],
    "suggest": true,
    "notes": "AES-256 en GCM. Cifrado autenticado, sin MAC aparte.",
    "references": ["RFC 5647"]
  }
}
```

| Field | Required | What it does |
|---|---|---|
| `category` | **yes** | One of the categories defined above. |
| `security_strength_bits` | no | Effective security bits. Feeds the overall strength and the standards. |
| `tags` | no | Tags. **This is the most useful thing in the whole file**, see below. |
| `suggest` | no | Whether this entry appears in the suggested `sshd_config` block. |
| `notes` | no | The why. Shown in the report with `--show-algorithm-notes`. |
| `references` | no | RFC, CVE, advisory. |

### Tags do the heavy lifting

A tag is a property that cuts across names: `cbc`, `sha1`, `aead`, `etm`,
`post-quantum`, `terrapin-vector`, `nist-curve`, `legacy`…

They matter because **detections and plugins reason by tag**, not by name. A
rule written against the `cbc` tag still works the day someone invents a new
CBC; one written against `aes128-cbc` does not.

Give them a readable name in `tag_labels`, which is what the report prints:

```json
"tag_labels": { "cbc": "CBC mode", "aead": "Authenticated encryption" }
```

Seven tags are not informational: they **trigger behaviour**, and Terrapin
detection, *encrypt-then-MAC* detection and the compression state rest on them,
not on the algorithm name:

| Tag | Effect |
|---|---|
| `post-quantum` | The algorithm counts toward the post-quantum state. |
| `aead` | Counts toward `require_aead_cipher`. |
| `etm` | Marks a MAC as *encrypt-then-MAC*: counts toward `require_etm_mac` and toward Terrapin's second vector. |
| `cbc` | Marks a cipher as CBC mode: together with an `etm` MAC it forms a Terrapin vector. |
| `terrapin-vector` | The cipher is exploitable by Terrapin on its own (ChaCha20-Poly1305). |
| `post-auth` | Compression only starts after authenticating: it decides the report's `Compression` state. |
| `protocol-marker` | Not an algorithm but a signal (`ext-info-s`, `kex-strict-*`): the profiles do not judge it. |

Over-tagging and under-tagging fail in different ways, so both boundary rules are
pinned by a test:

- **`protocol-marker` is skipped; everything else is judged.** Over-tagging is the
  same as no longer checking a real algorithm. That is why the `AEAD_AES_*_GCM`
  MACs do **not** carry it even though they are `informational`: they are real
  RFC 5647 names that CNSA 2.0 requires, not flags.
- **With `post-auth` the rule is the reverse:** whatever does *not* carry it is
  treated as pre-authentication. "Wait until you authenticate" is the claim that
  needs proof, so a new, unclassified compression comes out as `enabled BEFORE
  authentication` until someone tags it. A test checks that `zlib@openssh.com`
  carries it and `zlib` does not, because that tag is the only thing telling the
  two apart.

This is how aliases like `rijndael-cbc@lysator.liu.se` (which is AES-256-CBC but
does not end in `-cbc`) or vendor variants like `hmac-sha2-256-etm@ssh.com` are
recognized. If you add a new CBC cipher or EtM MAC, tag it or it stays out of the
check.

---

## Patterns: for what is not on the list yet

A pattern captures what the entries do not name, with shell-style
wildcards:

```json
"patterns": [
  {
    "match": "*-cbc*",
    "category": "weak",
    "tags": ["cbc"],
    "notes": "CBC mode not explicitly listed. In SSH it is encrypt-and-MAC."
  }
]
```

Entries beat patterns. Order matters: **the first pattern that matches is the
one that rules**, so put the specific before the general.

They are for two things: not having to enumerate forty variants of the same
thing, and making sure a new algorithm from a bad family does not come out as
*unknown* — which does not penalize — but with its family's category.

---

## Adding a new algorithm: the recipe

1. **Look for it first.** Does a pattern already catch it? `--show-policy`
   counts how many entries and patterns each class has.
2. Add the entry in the class it belongs to, with `category` and, if you know
   it, `security_strength_bits`.
3. **Give it tags**, even if they seem obvious. That is what will make other
   people's rules pick it up.
4. Write `notes` with the why and `references` with the source. Two years from
   now, whoever reads it will want to know what you based it on.
5. Set `suggest: true` only if you genuinely recommend putting it in an
   `sshd_config`.
6. Check it:

```bash
ssh-crypto-checker --config mi-politica.json --show-policy
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --show-algorithm-notes
```

---

## Key sizes: `requirements`

Besides the names, there are the sizes:

```json
"requirements": {
  "host_keys": {
    "rsa":     { "minimum_bits": 2048, "recommended_bits": 3072 },
    "ed25519": { "minimum_bits": 256,  "recommended_bits": 256 }
  },
  "dh_group": { "minimum_bits": 2048, "recommended_bits": 3072 }
}
```

`minimum_bits` is what triggers a serious finding (and can activate a grade
cap); `recommended_bits` is what triggers a warning. If you do not set
`recommended_bits`, it is taken to be the same as the minimum.
