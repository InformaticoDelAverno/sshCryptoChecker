# Guide to `fleet` plugins

> Before this, read [`plugins.md`](plugins.md).

A `fleet` sees **every server in the scan at once**. It exists for what
cannot be seen by looking at one machine, no matter how well you look.

The canonical example is the shared host key: two servers presenting the
same key is not a property of either one, it is a property **of the pair**.
No per-server check will ever find it, and the consequence is serious:
extracting the private key from the least important of those hosts is enough
to impersonate all of them, and no client notices the difference.

```python
KIND = "fleet"

def check(fleet):   # `fleet` es un FleetView
    ...
```

It runs **once per scan**, after everything has been scanned.

---

## What `fleet` is

A `FleetView`, which is a collection of servers:

| | |
|---|---|
| `for server in fleet` | Iterates over **all** the targets. |
| `len(fleet)` | How many there were. |
| `fleet.with_host_keys()` | Only those whose host key could be obtained. |
| `fleet.policy` | The policy, for asking for thresholds. |

Each element is a `ScannedServer`:

| | |
|---|---|
| `server.target` | The address exactly as the report prints it. |
| `server.label` | The inventory label, if it had one. |
| `server.view` | A `ServerView` identical to the one a `check` receives. |

> **The targets that failed are there too.** A server that refused the
> connection has an **empty** view, not a missing one. This matters far more
> than it seems: if the unreachable ones fell off the list, a check like
> "are all my servers on the same version?" would answer from the ones that
> happened to be up, and it would say yes.

So, when iterating, decide what to do with the ones that did not answer:

```python
for server in fleet:
    if server.view.banner is None:
        continue          # or count it -- but decide it
```

---

## What gets returned: each finding says whose it is

A `fleet` sees everything, so it has to say which server each result belongs
to. That is what `ForTarget` is for:

```python
from ssh_crypto_checker.models import Finding, Severity
from ssh_crypto_checker.plugins import ForTarget

return [ForTarget(target=server.target, finding=Finding(...))]
```

`target` is the address **exactly as the report prints it**, which is what
`server.target` holds. A `ForTarget` that names a target the scan did not
produce is discarded rather than invented.

If the finding is about the set and not about one specific machine, attach
it to the first target so it appears exactly once.

---

## A complete example

Every server should be on the same product version. If they are not, there
is a half-finished patch rollout — and that cannot be seen from any single
machine.

```python
"""Servidores del mismo parque en versiones distintas."""

from ssh_crypto_checker.models import Finding, Severity
from ssh_crypto_checker.plugins import ForTarget

ID = "fleet-version-drift"
NAME = "The fleet is not on the same version"
KIND = "fleet"
SEVERITY = "medium"
DESCRIPTION = (
    "Los servidores escaneados anuncian versiones distintas del mismo "
    "product. It usually means a patch rollout that stopped halfway, and the "
    "machine left behind is the one somebody will find."
)
REMEDIATION = "Update the ones left behind, or explain why not."


def check(fleet):
    por_version = {}
    for server in fleet:
        if server.view.banner is None:
            continue                      # did not answer: no opinion
        producto = server.view.product or "sin identificar"
        version = server.view.product_version or "no version"
        por_version.setdefault((producto, version), []).append(
            server.label or server.target
        )

    productos = {producto for producto, _ in por_version}
    hallazgos = []
    for producto in sorted(productos):
        versiones = {v: n for (p, v), n in por_version.items() if p == producto}
        if len(versiones) < 2:
            continue                      # todos iguales: nada que decir
        detalle = [
            f"{version}: {', '.join(sorted(nombres))}"
            for version, nombres in sorted(versiones.items())
        ]
        # Once per product, attached to the first affected server.
        primero = sorted(next(iter(versiones.values())))[0]
        objetivo = next(
            server.target for server in fleet
            if (server.label or server.target) == primero
        )
        hallazgos.append(ForTarget(
            target=objetivo,
            finding=Finding(
                id=ID,
                severity=Severity.MEDIUM,
                title=f"{producto} is on {len(versiones)} different versions",
                description=DESCRIPTION,
                remediation=REMEDIATION,
                items=detalle,
            ),
        ))
    return hallazgos
```

---

## The same boundary, with even more reason

A `fleet` sees the whole scan, and it **still cannot see anyone's grade**.
It can see that two servers present the same key; it cannot see, or move,
what either of them was given.

`server.view.assessment("cipher")` returns the classification (which is an
observation plus the policy's opinion); the score built from it is not there
and will not be.

---

## When **not** to write a `fleet`

If the question can be answered by looking at one server, write a `check`:
it is cheaper, it runs earlier and the finding comes out attached to its
machine without you having to say so. `fleet` is for what can **only** be
seen by comparing.
