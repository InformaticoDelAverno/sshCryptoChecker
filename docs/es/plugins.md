# Manual de plugins — el contrato común

Un plugin es **un fichero `.py`** con unas cuantas constantes y una función.
No hay que instalar nada, no hay que registrarse en ningún sitio y no hay
clases que heredar.

Este manual es el contrato que comparten los tres tipos. Después, según lo que
quieras mirar:

- [`plugin-check.md`](plugin-check.md) — un servidor.
- [`plugin-fleet.md`](plugin-fleet.md) — todos los servidores a la vez.
- [`plugin-vulnerability.md`](plugin-vulnerability.md) — una vulnerabilidad conocida.

---

## El plugin más corto que funciona

```python
"""El servidor anuncia su versión exacta en el banner."""

ID = "banner-reveals-version"
NAME = "El banner revela la versión exacta"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = "El servidor publica su versión completa antes de autenticar."
REMEDIATION = "Compila con una cadena de versión reducida, o pon un banner delante."

def check(server):
    if server.product_version:
        return [f"El banner dice {server.product} {server.product_version}"]
    return None
```

Guárdalo como `banner_version.py` en un directorio cualquiera y ejecútalo:

```bash
ssh-crypto-checker servidor.example.com --plugin-dir ./mis-plugins
```

Comprueba que cargó antes de escanear nada:

```bash
ssh-crypto-checker --list-plugins --plugin-dir ./mis-plugins
```

---

## Los metadatos

Cada plugin es un módulo con constantes en mayúsculas. Cuatro son
**obligatorias** y el cargador rechaza el fichero si falta alguna:

| Constante | Obligatoria | Qué es |
|---|---|---|
| `ID` | **sí** | Identificador estable del hallazgo. Aparece en el informe, en el JSON y en el SARIF, y es lo que alguien usará para silenciarlo o seguirlo entre escaneos. No lo cambies a la ligera. |
| `NAME` | **sí** | Título legible. Es lo que se lee en el informe. |
| `SEVERITY` | **sí** | `critical`, `high`, `medium`, `low` o `info`. Cualquier otra cosa es un error de carga con la lista de las válidas. |
| `DESCRIPTION` | **sí** | Qué significa el hallazgo. Escríbelo para alguien que no sabe por qué le aparece. |
| `KIND` | no (`vulnerability`) | `check`, `fleet` o `vulnerability`. **Ponlo siempre**: el valor por defecto no es el que quieres casi nunca. |
| `REMEDIATION` | no (`""`) | Qué hacer al respecto. Un hallazgo sin remedio es una queja. |
| `REFERENCES` | no (`[]`) | Lista de URLs o identificadores: el CVE, el RFC, el aviso del fabricante. |
| `AFFECTS` | no (`server`) | `server` o `client`. `client` es para lo que mira la configuración de **esta** máquina. |
| `NEEDS` | no (`[]`) | Qué datos necesita el plugin. Ver más abajo. |

## `NEEDS`: decir qué necesitas, en vez de fallar sin decirlo

Muchas comprobaciones solo tienen sentido si el escaneo recogió cierto dato, y
esos datos son **opcionales** (`--sshfp`, `--audit-config`…). Un plugin que
mira un dato que no se recogió y devuelve «nada» está diciendo «este servidor
está bien» cuando debería decir «no miré».

Por eso se declara:

```python
NEEDS = ["sshfp", "host_keys"]
```

Si el escaneo no trae esos datos, tu `check` **no se ejecuta** y el informe
dice que no se pudo evaluar y con qué opción habría que repetir. Los nombres
válidos son exactamente estos, y cualquier otro es un error de carga:

| Nombre | Qué necesita el escaneo |
|---|---|
| `banner` | Siempre presente si el servidor contestó. |
| `kexinit` | La lista de algoritmos. Siempre, si hubo negociación. |
| `host_keys` | Las claves de host (por defecto sí; `--no-host-keys` las quita). |
| `auth_methods` | `--auth-methods` |
| `sshfp` | `--sshfp` |
| `known_hosts` | `--known-hosts` |
| `login_grace` | `--login-grace` |
| `max_startups` | `--max-startups` |
| `config` | `--audit-config` (auditoría autenticada del servidor) |
| `client_config` | `--audit-client` |

---

## Qué puede devolver `check`

Todo esto vale, y el corredor lo normaliza:

| Devuelves | Significa |
|---|---|
| `None` o `False` o `[]` | No hay nada que informar. **Es el caso normal.** |
| `True` | Se cumple, con los metadatos del módulo tal cual. |
| `["texto", "texto"]` | Se cumple, y esas cadenas son la **evidencia**. |
| `Detected(...)` | Se cumple, con evidencia y opcionalmente sobreescribiendo severidad, título, descripción, remedio o incluso el `ID`. |
| `Undetermined(needs=[...])` | **No se pudo decidir**, y esto es lo que lo resolvería. No es lo mismo que decir que no. |
| `Finding(...)` | Un hallazgo construido a mano, si necesitas control total. |
| Una lista de cualquiera de los anteriores | Varios hallazgos de un mismo fichero. |

```python
from ssh_crypto_checker.plugins import Detected, Undetermined

def check(server):
    if server.config is None:
        return Undetermined(needs=["config"])
    valor = server.directive("clientaliveinterval")
    if valor and int(valor) > 3600:
        return Detected(
            evidence=[f"ClientAliveInterval = {valor}"],
            severity="medium",          # más grave de lo declarado, en este caso
            note="Una hora es mucho para una sesión sin actividad.",
        )
    return None
```

### La evidencia no es decorado

`evidence` es la diferencia entre «este servidor tiene un problema» y «este
servidor tiene *este* problema, mira». Pon el valor concreto que lo hizo
saltar: el algoritmo, la directiva y su valor, la huella. Quien lea el informe
tiene que poder verificarlo sin volver a escanear.

---

## Las tres cosas que un plugin **no** puede hacer

Esto no son consejos: son garantías comprobadas por la suite.

### 1. Un plugin no puede cambiar la nota

Recibe una **vista de observaciones**, no el resultado. Puede ver qué
algoritmos ofrece el servidor; **no** puede ver ni tocar la puntuación, la
nota ni el veredicto. Eso lo decide el fichero de política.

La razón es sencilla: si un plugin de un tercero pudiera mover la nota, la
nota dejaría de significar algo. Un auditor tiene que poder decir «esta A sale
de la política, y la política está aquí».

### 2. Un plugin no puede acabar con un escaneo

Si tu `check` lanza una excepción, cuesta **su propio resultado** y nada más:
el informe dice que ese plugin falló en ese servidor, y el escaneo sigue. No
hace falta que envuelvas nada en `try`.

### 3. Un plugin no puede meter en el informe algo que el modelo prohíbe

Una severidad inventada o bytes crudos donde va texto se normalizan en la
frontera. Antes no: una severidad mala tumbaba un objetivo y unos bytes
tumbaban el escaneo entero.

---


## La arquitectura: qué se envía como plugin, y qué no

**Casi todas las comprobaciones de la herramienta son plugins.** No es un sistema
para terceros con lo importante escondido en otro sitio: es el mecanismo, y se
usa. Doce ficheros de serie, uno por sujeto (`shared_host_keys` —de parque—,
`server_directives`, `server_files`, `server_accounts`, `client_audit`,
`auth_methods`, `host_certificates`, `sshfp_records`, `known_hosts_record`,
`preauth_capacity`, `rsa_key_quality`, `certificate_lifetime`); documentados en
`builtin/README.md`.

Dos cosas **no** son plugins, y el motivo importa:

- **Las 89 reglas declarativas del JSON.** Para emparejar un nombre, una ventana
  de versiones o el valor de una directiva son mejores que un plugin: sin código,
  sin ejecutar nada, editables por quien no programa. Un plugin es para lo que una
  regla *no puede expresar* — dividir un número, restar dos fechas, factorizar un
  módulo.
- **El modelo de puntuación.** La clasificación de algoritmos, el tamaño de las
  claves de host, la fuerza efectiva, la nota y los perfiles viven en
  `assessment.py`, no en un plugin. `analysis.py` pasó de **2165 a 362 líneas** al
  sacarle las comprobaciones, y ya no emite ninguna: lo que le queda es la salida
  del motor de vulnerabilidades, que son *resultados de un motor*, no juicios
  sobre un servidor.

### Las dos garantías, comprobadas y no supuestas

Las garantías de arriba —«un plugin no cambia la nota», «todo se ejecuta»— no se
confían a la disciplina: están fijadas por tests, porque son de las que dejan de
ser ciertas en cuanto alguien añade un fichero.

- **Ningún plugin puede cambiar la nota.** El test escanea el mismo servidor con
  todos los plugins y sin ninguno, y exige que `score`, `grade` y `verdict`
  coincidan — comprobando además que los **hallazgos sí difieren**, para que la
  comparación no sea vacua. Otro repite la prueba con un plugin que lanza una
  excepción.
- **Todo se ejecuta.** Un test verifica que ningún plugin quedó sin llamar, y
  otro falla si alguien vuelve a meter una comprobación en `analysis.py`.

### Por qué no hay un sistema de dependencias entre plugins

Hubo un problema de orden real: los plugins corrían antes de que el modelo
calculase el estado post-cuántico y veían `None`. Pero la causa **no era una
dependencia entre plugins**: era una sola dependencia compartida, «después del
modelo», y se resuelve ordenando el orquestador. Un grafo traería ciclos, orden
topológico y un canal para pasar datos de un plugin a otro — justo el acoplamiento
que se quiere evitar. Si un plugin necesita lo que calcula otro, la respuesta
correcta casi siempre es **poner ese dato en la vista**, donde ambos lo leen sin
conocerse. La única ordenación que existe es declarativa y ya está en el `KIND`:
los de parque corren después de los de servidor, porque no pueden correr antes.

### Los dos ejemplos que muestran el límite

- **`rsa_key_quality`** divide el módulo de la clave RSA por los primos menores de
  1000 y comprueba el exponente público. Una clave así no es *corta*, es
  **incorrecta**: se puede factorizar, y aun así se anuncia como un `rsa-sha2-512`
  de tamaño normal. Ninguna regla que empareje nombres la ve.
- **`certificate_lifetime`** mira para **cuánto tiempo se emitió** un certificado.
  La política sabe decir cuándo caduca *pronto* (una comparación con hoy), pero no
  para cuánto se emitió, porque eso es una resta. Un certificado de diez años ha
  regalado justo lo que un certificado compra sobre una clave desnuda: que la
  confianza caduque sola.

---

## Dónde se buscan los plugins, y qué se rechaza

```bash
ssh-crypto-checker --plugin-dir ./mis-plugins servidor.example.com
```

Se puede repetir `--plugin-dir`. Además se miran los directorios por defecto
que `--list-plugins` enseña.

**El directorio de trabajo nunca se busca.** Ejecutar la herramienta desde un
directorio con ficheros de otro no puede significar cargar código de otro.

Un fichero o un directorio **con permiso de escritura para el grupo o para
otros se rechaza**, con el motivo. Si cualquiera puede editar el fichero,
cualquiera puede ejecutar código como quien lanza el escaneo. El directorio
`builtin/` del propio paquete está exento, porque su integridad es la de la
instalación.

Un plugin que no carga **no acaba con nada**: se informa del fichero y del
motivo, y los demás se cargan. Compruébalo siempre con `--list-plugins`, que
enseña los que cargaron **y los que no**.

---

## Cómo probar tu plugin

Contra un servidor real que controles, o contra el laboratorio de este
repositorio:

```bash
cd lab && ./lab-setup.sh && docker compose up -d --build && cd ..
ssh-crypto-checker 127.0.0.1:2222 --plugin-dir ./mis-plugins --no-color
```

Y en una prueba, sin red, dándole una vista construida a mano:

```python
import unittest
from ssh_crypto_checker.plugins import ServerView

import mis_plugins.banner_version as plugin


class ElBannerRevelaLaVersion(unittest.TestCase):
    def test_lo_dice_cuando_hay_version(self):
        class Banner:
            product = "OpenSSH"
            product_version = "9.6p1"

        resultado = plugin.check(ServerView(banner=Banner()))
        self.assertTrue(resultado)

    def test_calla_cuando_no_la_hay(self):
        self.assertFalse(plugin.check(ServerView()))
```

`ServerView()` sin argumentos es un escaneo que no recogió nada, y **todos**
sus accesos tienen respuesta. Es el caso que más se olvida y el que más rompe
plugins escritos contra un escaneo completo.

---

## Errores frecuentes

| Síntoma | Causa |
|---|---|
| El plugin no aparece en `--list-plugins` | Permisos del fichero o del directorio: si el grupo u otros pueden escribir, se rechaza. Míralo con `ls -l`. |
| Aparece como rechazado con «missing ID, NAME…» | Falta una de las cuatro constantes obligatorias. |
| «SEVERITY … is not one of» | Solo `critical`, `high`, `medium`, `low`, `info`. |
| «NEEDS names …, which is not collected» | Un nombre de `NEEDS` que no existe; el mensaje lista los válidos. |
| Nunca salta, y debería | ¿Has escrito bien el nombre de la clase de algoritmo? `server.algorithms("cypher")` lanza `ValueError` a propósito, justo para que no falle en silencio. |
| Salta en todos los servidores | Probablemente devuelves `[]`, que es falso, pero `[""]` es verdadero. |
