# Guide to `check` plugins

> Before this, read [`plugins.md`](plugins.md): the metadata, what can be
> returned and the three things a plugin cannot do are common to all three
> kinds.

A `check` looks at **one server** and gives an opinion about it. It is the
kind you want almost every time: twelve of the fifteen checks the tool ships
with are of this kind.

```python
KIND = "check"

def check(server):   # `server` es un ServerView
    ...
```

---

## What `server` is

A `ServerView`: **what was observed**, and none of what was concluded. It has
no score, no grade, no verdict, and it never will.

Everything below has an answer even if the scan collected nothing. A scan
with `--no-host-keys` gives `server.host_keys == []`, not an error.

### The banner

| | |
|---|---|
| `server.product` | `"OpenSSH"`, `"Dropbear"`, `""` if it could not be identified. |
| `server.product_version` | `"9.6p1"`, or `""`. |
| `server.protocol_version` | `"2.0"`, `"1.99"`… |
| `server.banner` | The full object, `raw` included. |
| `server.version_in_range("8.5p1", "9.8p1")` | Whether the advertised version falls in `[introduced, fixed)`. Returns `False` when there is no version, which is the prudent answer. |

### The algorithms

The five classes are `kex`, `host_key`, `cipher`, `mac` and `compression`.

| | |
|---|---|
| `server.algorithms("cipher")` | Everything the server offers in that class. |
| `server.offers("kex", "curve25519-sha256")` | Whether it offers that specific one. |
| `server.tags("cipher", "aes128-cbc")` | The tags the policy puts on it: `["cbc"]`, `["terrapin-vector"]`… Reasoning by tag instead of by name keeps your plugin working when a new algorithm shows up. |
| `server.assessment("kex")` | The classification of that class against the policy. |

> **A misspelled class name raises `ValueError`.** On purpose: an empty list
> would be a plugin that never fires, which reads exactly like a server with
> no problems.

### The host keys

`server.host_keys` is a list; each element carries `algorithm`,
`key_family` (`rsa`, `ed25519`, `ecdsa`, `dsa`, `ed448`…), `bits`,
`fingerprint_sha256`, `is_certificate`, `certificate` and `error`.

**Check `error` before using the rest.** A key that could not be read has
`bits` at zero, and treating it as a 0-bit key invents a finding out of a
network failure.

```python
for key in server.host_keys:
    if key.error is not None or not key.bits:
        continue
    ...
```

### The negotiation

| | |
|---|---|
| `server.strict_kex` | Whether the server negotiates strict key exchange. |
| `server.post_quantum` | The post-quantum status. |
| `server.dh_group_bits` | The size of the Diffie-Hellman group that was used, if applicable. |

### The optional probes

Each one needs its `NEEDS` entry (and its command-line option):

| | `NEEDS` | |
|---|---|---|
| `server.auth_methods` | `auth_methods` | Accepted methods, and `accepted_without_credentials`. |
| `server.sshfp` | `sshfp` | Comparison against the SSHFP records. |
| `server.known_hosts` | `known_hosts` | Comparison against the local `known_hosts`. |
| `server.login_grace_seconds` | `login_grace` | Measured seconds. |
| `server.max_startups` | `max_startups` | Connections accepted before refusal. |

### The configuration

| | `NEEDS` | |
|---|---|---|
| `server.directive("permitrootlogin")` | `config` | A directive exactly as `sshd -T` resolved it, in lowercase. `None` if it was not read. |
| `server.client_directive("ciphers")` | `client_config` | The same for this machine's client. |
| `server.config` | `config` | The full object: file permissions, `moduli`, package, accounts. |

### The thresholds

**Do not hardcode numbers.** Ask the policy for them; that is where they can
be changed without deploying:

```python
requisito = server.requirement("host_key_requirements")
```

`server.requirement(name, default)` reads an attribute of the policy. A
plugin that carries its own `2048` inside is a second place to update and a
second place to forget.

---

## A complete example

A server that offers CBC ciphers **and** MACs in `encrypt-then-MAC` mode is
the Terrapin condition via the block-cipher route. The interesting part: it
reasons by **tags**, not by names, so it will still hold when someone adds a
CBC cipher that does not exist today.

```python
"""Cifrados CBC combinados con MAC en modo encrypt-then-MAC."""

ID = "cbc-with-etm"
NAME = "CBC junto a MAC en modo encrypt-then-MAC"
KIND = "check"
SEVERITY = "medium"
AFFECTS = "server"
NEEDS = ["kexinit"]
DESCRIPTION = (
    "El servidor ofrece cifrados en modo CBC y MAC en modo encrypt-then-MAC. "
    "That combination is one of the two ways to be vulnerable to Terrapin "
    "(CVE-2023-48795) cuando no hay contramedida de intercambio estricto."
)
REMEDIATION = (
    "Quita los cifrados -cbc de la directiva Ciphers, o actualiza a una "
    "version that implements kex-strict-s-v00@openssh.com."
)
REFERENCES = ["CVE-2023-48795", "https://terrapin-attack.com/"]


def check(server):
    cbc = [
        nombre for nombre in server.algorithms("cipher")
        if "cbc" in server.tags("cipher", nombre)
    ]
    etm = [
        nombre for nombre in server.algorithms("mac")
        if "etm" in server.tags("mac", nombre)
    ]
    if not (cbc and etm):
        return None
    if server.strict_kex:
        return None          # con la contramedida puesta, no es explotable

    return [
        f"cifrados CBC: {', '.join(sorted(cbc))}",
        f"MAC en modo ETM: {', '.join(sorted(etm))}",
    ]
```

Note the three decisions:

1. **It returns `None` when there is nothing to say**, which is the normal
   case.
2. **The countermeasure is checked before reporting**: a finding that is not
   exploitable on that server is noise, and noise gets everything else ignored.
3. **The evidence says exactly which algorithms**, not "there is CBC".

---

## Reporting several things from one file

If your check has several related results, return them together and give
each one its own `id`. That beats splitting the same analysis across six
files that have to be maintained in step:

```python
from ssh_crypto_checker.plugins import Detected

def check(server):
    hallazgos = []
    for key in server.host_keys:
        if key.error is not None:
            continue
        if key.key_family == "rsa" and key.bits and key.bits < 3072:
            hallazgos.append(Detected(
                id="rsa-below-recommended",
                name="Clave RSA por debajo de lo recomendado",
                evidence=[f"{key.algorithm} de {key.bits} bits"],
                severity="low",
            ))
        if key.is_certificate and key.certificate and not key.certificate.key_id:
            hallazgos.append(Detected(
                id="certificate-without-key-id",
                name="Certificado de host sin identificador",
                evidence=[key.fingerprint_sha256],
            ))
    return hallazgos
```

---

## When **not** to write a `check`

- **If the check is "this algorithm is bad"**: that is an entry in the
  policy file, not code. See [`politica-algoritmos.md`](politica-algoritmos.md).
- **If it is "this directive should be set to X"**: not code either. See
  [`politica-configuracion.md`](politica-configuracion.md).
- **If you need to compare servers against each other**: that is a `fleet`. See
  [`plugin-fleet.md`](plugin-fleet.md).
