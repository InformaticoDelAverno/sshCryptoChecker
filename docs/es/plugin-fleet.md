# Manual de plugins de tipo `fleet`

> Antes de esto, lee [`plugins.md`](plugins.md).

Un `fleet` ve **todos los servidores del escaneo a la vez**. Existe para lo que
no se puede ver mirando una máquina, por bien que la mires.

El ejemplo canónico es la clave de host compartida: que dos servidores
presenten la misma clave no es una propiedad de ninguno de los dos, es una
propiedad **de la pareja**. Ninguna comprobación por servidor lo encontrará
jamás, y la consecuencia es seria: sacar la clave privada del menos importante
de esos hosts basta para suplantar a todos, y ningún cliente nota la
diferencia.

```python
KIND = "fleet"

def check(fleet):   # `fleet` es un FleetView
    ...
```

Se ejecuta **una vez por escaneo**, cuando ya se ha escaneado todo.

---

## Qué es `fleet`

Un `FleetView`, que es una colección de servidores:

| | |
|---|---|
| `for server in fleet` | Recorre **todos** los objetivos. |
| `len(fleet)` | Cuántos había. |
| `fleet.with_host_keys()` | Solo aquellos a los que se les pudo sacar la clave de host. |
| `fleet.policy` | La política, para pedir umbrales. |

Cada elemento es un `ScannedServer`:

| | |
|---|---|
| `server.target` | La dirección tal y como el informe la imprime. |
| `server.label` | La etiqueta del inventario, si tenía. |
| `server.view` | Un `ServerView` idéntico al que recibe un `check`. |

> **Los objetivos que fallaron también están.** Un servidor que rechazó la
> conexión tiene una vista **vacía**, no ausente. Esto importa mucho más de lo
> que parece: si los inalcanzables se cayeran de la lista, una comprobación
> como «¿están todos mis servidores en la misma versión?» contestaría desde
> los que casualmente estaban levantados, y diría que sí.

Por eso, al recorrer, decide qué hacer con los que no contestaron:

```python
for server in fleet:
    if server.view.banner is None:
        continue          # o cuéntalo, pero decídelo
```

---

## Qué se devuelve: cada hallazgo dice de quién es

Un `fleet` lo ve todo, así que tiene que decir a qué servidor pertenece cada
resultado. Para eso está `ForTarget`:

```python
from ssh_crypto_checker.models import Finding, Severity
from ssh_crypto_checker.plugins import ForTarget

return [ForTarget(target=server.target, finding=Finding(...))]
```

`target` es la dirección **tal y como el informe la imprime**, que es lo que
hay en `server.target`. Un `ForTarget` que nombra un objetivo que el escaneo no
produjo se descarta en vez de inventarlo.

Si el hallazgo es sobre el conjunto y no sobre una máquina concreta, engánchalo
al primer objetivo para que aparezca exactamente una vez.

---

## Un ejemplo completo

Todos los servidores deberían estar en la misma versión del producto. Si no lo
están, hay un parcheo a medias — y eso no se ve desde ninguna máquina.

```python
"""Servidores del mismo parque en versiones distintas."""

from ssh_crypto_checker.models import Finding, Severity
from ssh_crypto_checker.plugins import ForTarget

ID = "fleet-version-drift"
NAME = "El parque no está en la misma versión"
KIND = "fleet"
SEVERITY = "medium"
DESCRIPTION = (
    "Los servidores escaneados anuncian versiones distintas del mismo "
    "producto. Suele significar un parcheo que se quedó a medias, y la "
    "máquina que se quedó atrás es la que alguien va a encontrar."
)
REMEDIATION = "Actualiza las que se quedaron atrás, o explica por qué no."


def check(fleet):
    por_version = {}
    for server in fleet:
        if server.view.banner is None:
            continue                      # no contestó: no opina
        producto = server.view.product or "sin identificar"
        version = server.view.product_version or "sin versión"
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
        # Una vez por producto, colgado del primer servidor afectado.
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
                title=f"{producto} está en {len(versiones)} versiones distintas",
                description=DESCRIPTION,
                remediation=REMEDIATION,
                items=detalle,
            ),
        ))
    return hallazgos
```

---

## La misma frontera, con más razón

Un `fleet` ve todo el escaneo, y **sigue sin poder ver la nota de nadie**.
Puede ver que dos servidores presentan la misma clave; no puede ver, ni mover,
lo que se le puso a ninguno de los dos.

`server.view.assessment("cipher")` devuelve la clasificación (que es una
observación más la opinión de la política); la puntuación construida a partir
de ella no está ahí y no lo estará.

---

## Cuándo **no** escribir un `fleet`

Si la pregunta se contesta mirando un servidor, escribe un `check`: es más
barato, se ejecuta antes y el hallazgo sale asociado a su máquina sin que
tengas que decirlo. `fleet` es para lo que **solo** se ve comparando.
