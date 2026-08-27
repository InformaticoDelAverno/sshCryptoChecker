# Manual de plugins de tipo `check`

> Antes de esto, lee [`plugins.md`](plugins.md): los metadatos, lo que se
> puede devolver y las tres cosas que un plugin no puede hacer son comunes a
> los tres tipos.

Un `check` mira **un servidor** y opina sobre él. Es el tipo que quieres casi
siempre: doce de las quince comprobaciones que trae la herramienta lo son.

```python
KIND = "check"

def check(server):   # `server` es un ServerView
    ...
```

---

## Qué es `server`

Un `ServerView`: **lo que se observó**, y nada de lo que se concluyó. No tiene
puntuación, ni nota, ni veredicto, y nunca los tendrá.

Todo lo de abajo tiene respuesta aunque el escaneo no recogiera nada. Un
escaneo con `--no-host-keys` da `server.host_keys == []`, no un error.

### El banner

| | |
|---|---|
| `server.product` | `"OpenSSH"`, `"Dropbear"`, `""` si no se pudo identificar. |
| `server.product_version` | `"9.6p1"`, o `""`. |
| `server.protocol_version` | `"2.0"`, `"1.99"`… |
| `server.banner` | El objeto completo, con `raw` incluido. |
| `server.version_in_range("8.5p1", "9.8p1")` | Si la versión anunciada cae en `[introducida, corregida)`. Devuelve `False` cuando no hay versión, que es lo prudente. |

### Los algoritmos

Las cinco clases son `kex`, `host_key`, `cipher`, `mac` y `compression`.

| | |
|---|---|
| `server.algorithms("cipher")` | Todo lo que el servidor ofrece en esa clase. |
| `server.offers("kex", "curve25519-sha256")` | Si ofrece ese en concreto. |
| `server.tags("cipher", "aes128-cbc")` | Las etiquetas que la política le pone: `["cbc"]`, `["terrapin-vector"]`… Razonar por etiqueta en vez de por nombre hace que tu plugin siga funcionando cuando aparezca un algoritmo nuevo. |
| `server.assessment("kex")` | La clasificación de esa clase contra la política. |

> **Un nombre de clase mal escrito lanza `ValueError`.** A propósito: una lista
> vacía sería un plugin que nunca salta, que se lee exactamente igual que un
> servidor sin problemas.

### Las claves de host

`server.host_keys` es una lista; cada elemento trae `algorithm`,
`key_family` (`rsa`, `ed25519`, `ecdsa`, `dsa`, `ed448`…), `bits`,
`fingerprint_sha256`, `is_certificate`, `certificate` y `error`.

**Comprueba `error` antes de usar el resto.** Una clave que no se pudo leer
tiene `bits` a cero, y tratarla como una clave de 0 bits inventa un hallazgo a
partir de un fallo de red.

```python
for key in server.host_keys:
    if key.error is not None or not key.bits:
        continue
    ...
```

### La negociación

| | |
|---|---|
| `server.strict_kex` | Si el servidor negocia intercambio estricto de claves. |
| `server.post_quantum` | El estado post-cuántico. |
| `server.dh_group_bits` | El tamaño del grupo Diffie-Hellman que se usó, si aplica. |

### Las sondas opcionales

Cada una necesita su `NEEDS` (y su opción en la línea de órdenes):

| | `NEEDS` | |
|---|---|---|
| `server.auth_methods` | `auth_methods` | Métodos aceptados, y `accepted_without_credentials`. |
| `server.sshfp` | `sshfp` | Comparación con los registros SSHFP. |
| `server.known_hosts` | `known_hosts` | Comparación con el `known_hosts` local. |
| `server.login_grace_seconds` | `login_grace` | Segundos medidos. |
| `server.max_startups` | `max_startups` | Conexiones aceptadas antes del rechazo. |

### La configuración

| | `NEEDS` | |
|---|---|---|
| `server.directive("permitrootlogin")` | `config` | Una directiva tal y como `sshd -T` la resolvió, en minúsculas. `None` si no se leyó. |
| `server.client_directive("ciphers")` | `client_config` | Lo mismo para el cliente de esta máquina. |
| `server.config` | `config` | El objeto completo: permisos de ficheros, `moduli`, paquete, cuentas. |

### Los umbrales

**No metas números en el código.** Pídeselos a la política, que es donde se
pueden cambiar sin desplegar:

```python
requisito = server.requirement("host_key_requirements")
```

`server.requirement(nombre, por_defecto)` lee un atributo de la política. Un
plugin que lleva su propio `2048` dentro es un segundo sitio que actualizar y
un segundo sitio que olvidar.

---

## Un ejemplo completo

Un servidor que ofrece cifrados CBC **y** MAC en modo `encrypt-then-MAC` es la
condición de Terrapin por la vía de los cifrados de bloque. Lo interesante:
razona por **etiquetas**, no por nombres, así que seguirá valiendo cuando
alguien añada un CBC que hoy no existe.

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
    "Esa combinación es una de las dos formas de ser vulnerable a Terrapin "
    "(CVE-2023-48795) cuando no hay contramedida de intercambio estricto."
)
REMEDIATION = (
    "Quita los cifrados -cbc de la directiva Ciphers, o actualiza a una "
    "versión que implemente kex-strict-s-v00@openssh.com."
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

Fíjate en las tres decisiones:

1. **Devuelve `None` cuando no hay nada que decir**, que es lo normal.
2. **La contramedida se comprueba antes de informar**: un hallazgo que no es
   explotable en ese servidor es ruido, y el ruido hace que se ignore el resto.
3. **La evidencia dice qué algoritmos exactamente**, no «hay CBC».

---

## Informar de varias cosas desde un fichero

Si tu comprobación tiene varios resultados relacionados, devuélvelos juntos y
dale a cada uno su propio `id`. Es mejor que partir el mismo análisis en seis
ficheros que hay que mantener a la vez:

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

## Cuándo **no** escribir un `check`

- **Si la comprobación es «este algoritmo es malo»**: eso es una entrada en el
  fichero de política, no código. Ver [`politica-algoritmos.md`](politica-algoritmos.md).
- **Si es «esta directiva debería valer X»**: tampoco. Ver
  [`politica-configuracion.md`](politica-configuracion.md).
- **Si necesitas comparar servidores entre sí**: es un `fleet`. Ver
  [`plugin-fleet.md`](plugin-fleet.md).
