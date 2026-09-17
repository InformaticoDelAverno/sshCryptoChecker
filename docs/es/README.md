# sshCryptoChecker

Auditoría de la criptografía que negocian tus servidores SSH: intercambio de
claves, claves de host, cifrado, MAC y compresión. Clasifica cada servidor como
**seguro**, **aceptable**, **débil** o **inseguro**, indica si está **preparado
para post-cuántico**, y genera el bloque de `sshd_config` que corrige lo que
encuentre.

Las listas de algoritmos viven en un **fichero de configuración editable**, no
en el código: lo que hoy es seguro mañana puede no serlo, y actualizar la
herramienta debe ser editar un JSON, no tocar Python.

> La herramienta habla **inglés y español**: el asistente, la ayuda y los
> informes siguen `--lang {en,es}` (sin él, el idioma del sistema). Los
> formatos para máquinas (json, sarif, csv, openmetrics) conservan sus claves
> en inglés a propósito.

---

> **English:** this manual is also available in [English](../en/README.md).

## Índice

- [Características](#características)
- [Requisitos e instalación](#requisitos-e-instalación)
- [Uso rápido](#uso-rápido)
- [Formas de indicar un objetivo](#formas-de-indicar-un-objetivo)
- [El asistente interactivo (--wizard)](#el-asistente-interactivo---wizard)
- [Idiomas (--lang)](#idiomas---lang)
- [Formatos de informe](#formatos-de-informe)
- [Uso avanzado](#uso-avanzado)
- [Vulnerabilidades conocidas](#vulnerabilidades-conocidas)
- [Plugins de detección](#plugins-de-detección)
- [El fichero de políticas](#el-fichero-de-políticas)
- [Conformidad con estándares (NIST, FIPS, ENS, PCI DSS, ISO…)](#conformidad-con-estándares-nist-fips-ens-pci-dss-iso)
- [Cómo se calcula la nota](#cómo-se-calcula-la-nota)
- [Qué comprueba exactamente](#qué-comprueba-exactamente)
- [Códigos de salida e integración en CI](#códigos-de-salida-e-integración-en-ci)
- [Las tres interfaces](#las-tres-interfaces)
- [Interfaz web](#interfaz-web)
- [Interfaz MCP](#interfaz-mcp)
- [Referencia de opciones](#referencia-de-opciones)
- [Recetario: un ejemplo por opción](#recetario-un-ejemplo-por-opción)
- [Auditoría autenticada de la configuración](#auditoría-autenticada-de-la-configuración)
- [Limitaciones y notas legales](#limitaciones-y-notas-legales)
- [Licencia](#licencia)
- [Guías de extensión incluidas](#guías-de-extensión-incluidas)

---

## Características

- **Sin dependencias.** Solo la biblioteca estándar de Python 3.9+. Se puede
  copiar a un bastión y ejecutar directamente.
- **Habla SSH de verdad.** Implementa la capa de transporte (RFC 4253): lee el
  `SSH_MSG_KEXINIT` del servidor y, opcionalmente, completa un intercambio de
  claves para obtener la clave de host real (tipo, tamaño y huella).
- **Nunca autentica.** No envía usuario ni contraseña ni datos de sesión: cierra
  la conexión en cuanto tiene la información.
- **Post-cuántico.** Detecta los métodos híbridos (`mlkem768x25519-sha256`,
  `sntrup761x25519-sha512@openssh.com`, …) y distingue entre *no preparado*,
  *preparado* y *forzado*.
- **Vulnerabilidades conocidas.** Terrapin, Sweet32, Logjam, recuperación de
  texto plano en CBC, firmas SHA-1, regreSSHion y más. **Las reglas de detección
  viven en el JSON**, así que añadir una nueva no requiere tocar código.
- **Certificados de host.** Extrae número de serie, identificador, principales,
  ventana de validez y huella de la CA; avisa de certificados caducados o a
  punto de caducar.
- **Cuatro formatos de salida:** consola con color, texto plano, JSON y HTML
  autocontenido.
- **Sugerencias aplicables.** El `sshd_config` propuesto se limita a algoritmos
  que el servidor ya admite, de modo que aplicarlo no deja a nadie fuera.
- **Más allá de los algoritmos.** Métodos de autenticación aceptados (completando
  un intercambio de claves real), registros SSHFP en DNS, `LoginGraceTime`
  medido, y detección de claves de host compartidas entre servidores.
- **Conformidad con normas.** Fuerza de seguridad efectiva en bits (NIST
  SP 800-57) y evaluación contra veinticinco perfiles, cada uno **verificado contra el
  documento publicado** y declarando la edición concreta: NIST SP 800-131A,
  FIPS 140-3, CNSA 1.0 y 2.0, BSI TR-02102-4, ENS, PCI DSS v4.0, CIS, ANSSI e
  ISO/IEC 27001 A.8.24.

---

## Requisitos e instalación

Python 3.9 o superior. Nada más.

### Opción 1: ejecutar desde el repositorio (sin instalar)

```bash
git clone https://github.com/CHANGEME/sshCryptoChecker.git
cd sshCryptoChecker
./ssh-crypto-checker servidor.example.com
```

O bien, de forma equivalente:

```bash
python3 -m ssh_crypto_checker servidor.example.com
```

### Opción 2: instalar

```bash
pip install .
ssh-crypto-checker servidor.example.com
```

En un entorno aislado:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

---

## Uso rápido

Sin argumentos, el script muestra la ayuda completa con ejemplos:

```bash
ssh-crypto-checker
```

¿No te quieres aprender las opciones? El **asistente interactivo** las pregunta
una a una y al final te muestra —y lanza— el comando construido:

```bash
ssh-crypto-checker --wizard
```

Escanear un servidor:

```bash
ssh-crypto-checker servidor.example.com
ssh-crypto-checker 192.0.2.10:2222
ssh-crypto-checker '[2001:db8::1]:22'
```

Varios servidores a la vez:

```bash
ssh-crypto-checker web01.example.com db01.example.com:2222 192.0.2.10
```

Desde un inventario, generando informe HTML:

```bash
ssh-crypto-checker -f inventario.txt --format html -o auditoria.html
```

Solo la tabla resumen (útil con muchos servidores):

```bash
ssh-crypto-checker -f inventario.txt --summary-only
```

Con la explicación de cada algoritmo:

```bash
ssh-crypto-checker servidor.example.com --notes
```

Contra qué normativas se evalúa — **por defecto, todas** (25); con `--profile` eliges
una, un subconjunto o una edición concreta:

```bash
ssh-crypto-checker servidor.example.com                       # todas
ssh-crypto-checker servidor.example.com --profile ens,pci-dss-4   # solo esas dos
ssh-crypto-checker servidor.example.com --profile disa-stig-rhel-9-ssh
```

Los identificadores salen con `--list-profiles`. La selección completa —subconjuntos,
`nombre@edición`, y la puerta de CI `--require-profile`— está en la sección
**«Conformidad con estándares»** más abajo.

---

## Formas de indicar un objetivo

| Forma | Ejemplo | Puerto |
|---|---|---|
| Nombre DNS | `servidor.example.com` | 22 (o `-p`) |
| Nombre DNS y puerto | `servidor.example.com:2222` | 2222 |
| IPv4 | `192.0.2.10` | 22 |
| IPv4 y puerto | `192.0.2.10:2222` | 2222 |
| IPv6 entre corchetes | `[2001:db8::1]:22` | 22 |
| IPv6 sin corchetes | `2001:db8::1` | 22 |
| URL | `ssh://servidor.example.com:2222` | 2222 |
| Con usuario (se ignora) | `admin@servidor.example.com` | 22 |

Un IPv6 sin corchetes **no** puede llevar puerto: no habría forma de
distinguirlo de otro grupo de la dirección.

---

## El asistente interactivo (--wizard)

Si no te quieres aprender las opciones, el asistente (`-w` / `--wizard`) las
pregunta una a una —objetivos e inventario, puerto, normativas a evaluar,
formatos de salida y fichero, tiempos y concurrencia, claves de host y
comprobaciones remotas, auditoría autenticada y plugins—, **muestra el comando**
que ha construido y ofrece lanzarlo:

```bash
ssh-crypto-checker --wizard
ssh-crypto-checker -w            # atajo
```

El asistente **no escanea nada por su cuenta**: ensambla el `argv` exacto que
usaría una invocación normal, lo imprime como una orden copiable y se la pasa a
la propia CLI. Así lo que muestra y lo que ejecuta son lo mismo por construcción,
y el comando impreso se puede **guardar y volver a lanzar** después sin el
asistente. Termina en `--lang`, para que copiado a otra máquina produzca el mismo
informe. Necesita un terminal interactivo (si la entrada no es un TTY, sale con
un aviso).

---

## Idiomas (--lang)

La herramienta es **bilingüe**: inglés (por defecto) y español de España. Todo lo
que lee una persona sale en el idioma elegido: el **asistente** (`--wizard`), la
**ayuda completa de la CLI** (`--help`: la descripción, la ayuda de cada opción y
las metavariables) y el **cuerpo de los informes** legibles (`console`, `text` y
`html`). Se elige así:

```bash
ssh-crypto-checker servidor.example.com --lang es      # español
ssh-crypto-checker servidor.example.com --lang en      # inglés (por defecto)
```

Sin `--lang`, se elige el español cuando el **locale** del sistema es español
(`LANG`/`LC_ALL`/`LC_MESSAGES` empieza por `es`); en cualquier otro caso, inglés.
`--lang` manda siempre sobre el locale, y admite formas como `es_ES` o `en-GB` (se
toma el prefijo). Los **formatos legibles por máquina** (JSON, SARIF, CSV,
inventory, OpenMetrics) conservan sus claves y valores en inglés sea cual sea el
idioma: son un contrato para herramientas, no prosa para personas. Las palabras
del armazón de `argparse` (`usage:`, `options:` y los errores de sintaxis) también
quedan en inglés, porque Python no trae su traducción.

---

## Formatos de informe

`--format` acepta `console` (por defecto), `txt`, `json`, `html`, `csv`, `sarif`,
`inventory` y `openmetrics`. Se puede repetir o separar por comas.

```bash
# a pantalla
ssh-crypto-checker servidor.example.com

# a fichero: cada formato añade su extensión si la ruta no la tiene ya
ssh-crypto-checker servidor.example.com --format html -o informe
# -> informe.html   (y 'informe.html' no se duplica a 'informe.html.html')

# varios formatos: -o es el nombre base y cada uno añade su extensión
ssh-crypto-checker -f inventario.txt --format json,txt,html -o informes/auditoria
# -> informes/auditoria.json, informes/auditoria.txt, informes/auditoria.html
```

- **`console`** — coloreado, con detección automática de terminal. Respeta
  `NO_COLOR` y `FORCE_COLOR`; se fuerza con `--color always|never`.
- **`txt`** — texto plano sin secuencias de escape, con cabecera de documento,
  tabla resumen y un apéndice que explica cómo leerlo. Pensado para adjuntar a
  un ticket o un correo.
- **`json`** — documento versionado (`schema_version`) con **todo** lo
  observado, incluidas las listas de algoritmos en crudo, el desglose de la
  puntuación y los tiempos. Pensado para cuadros de mando y series históricas.
- **`html`** — un único fichero autocontenido: sin fuentes, scripts ni hojas de
  estilo externas, por lo que no filtra nada a la red al abrirlo. Se adapta al
  tema claro/oscuro del lector y se imprime bien.
- **`csv`** — una fila por hallazgo, con las columnas del servidor repetidas en
  cada una. Es lo que hace falta para filtrar un parque entero por severidad en
  una hoja de cálculo, o para importar el trabajo pendiente a un gestor de
  incidencias. Un servidor sin hallazgos también genera su fila, para que se
  distinga un servidor sano de uno que no se escaneó.
- **`sarif`** — SARIF 2.1.0, el formato que ingieren GitHub code scanning, Azure
  DevOps y varios cuadros de mando. Cada servidor es un *artifact* con URI
  `ssh://host:puerto`, cada hallazgo un *result*, y el identificador del hallazgo
  la regla. Las huellas (`partialFingerprints`) son estables entre ejecuciones,
  así que el cuadro de mando distingue un hallazgo que reaparece de uno nuevo.
- **`inventory`** — el inventario criptográfico en Markdown, con el formato que
  pide **PCI DSS v4.0 requisito 12.3.3**: sistemas en alcance, cada algoritmo
  una sola vez con los servidores que lo ofrecen, los que hay que retirar, la
  posición ante la criptografía post-cuántica y la estrategia de respuesta. Ver
  [Conformidad](#conformidad-con-estándares-nist-fips-ens-pci-dss-iso).

- **`openmetrics`** — formato de exposición de Prometheus, para escribir
  directamente en el directorio del *textfile collector* de node_exporter. Un
  informe responde a una pregunta que alguien hizo; las métricas responden a las
  que nadie está despierto para hacer: un servidor cuya nota bajó de madrugada,
  un parque cuya cobertura post-cuántica dejó de subir, un escaneo que dejó de
  ejecutarse en silencio. La nota se exporta como **ordinal** (0 es A+) y no
  como etiqueta, porque «la nota ha empeorado» es la alerta que se quiere y con
  etiquetas no se puede expresar: `ssh_target_grade > 2`.

Las extensiones al escribir varios formatos son `.console.txt`, `.txt`,
`.json`, `.html`, `.csv`, `.sarif.json`, `.inventory.md` y `.prom`.

Al escribir a fichero nunca se emiten códigos de color, aunque se pida
`--color always`.

---

## Uso avanzado

Más allá del escaneo básico, la herramienta compara con un escaneo anterior
(`--compare`), audita el cliente `ssh` de esta máquina (`--audit-client`),
escanea a través de un bastión, lee objetivos y credenciales de un **fichero de
inventario** (`-f`, con `user=`, `auth=`, `key=`, `password-env=`) y hace
comprobaciones remotas adicionales (SSHFP en DNS con `--sshfp`, `known_hosts`
local con `--known-hosts`, gracia de login…). Cada una tiene su ejemplo en el
[Recetario](#recetario-un-ejemplo-por-opción); el cómo y el porqué de cada una,
con todo el detalle, en [`docs/uso-avanzado.md`](uso-avanzado.md).

---

## Vulnerabilidades conocidas

Además de clasificar algoritmos, la herramienta comprueba **65 vulnerabilidades
concretas** en OpenSSH, Dropbear y libssh (49 del servidor, 14 del cliente de esa
misma máquina). Lo importante del diseño: **la detección vive en el JSON, no en el
código** — añadir una es editar una lista, sin tocar Python.

```bash
ssh-crypto-checker --list-vulnerabilities
```

Se detectan por tres caminos: **en la conexión** (10, lo que el servidor ofrece de
verdad, sin margen de error), **por versión** (54, deducidas del banner, siempre
con la advertencia de que las distros retroportan parches sin cambiar el número) y
**condicionadas a la configuración** (4, que exigen `--audit-config`). La regla que
gobierna esta sección: **no mirar no es lo mismo que mirar y no encontrar nada** —
una comprobación que necesita datos que el escaneo no recogió sale *no
determinada*, con la opción que la resolvería, nunca como «no afectado».

Las vulnerabilidades tienen **su propia sección** del informe, separada de los
hallazgos de configuración, porque responden a otra pregunta: un hallazgo dice que
el servidor está configurado de una forma que la política desaprueba; una
vulnerabilidad, que alguien publicó un ataque contra el software que ejecuta. El
resumen del parque las ordena por cuántas máquinas comparten cada problema
(`by_vulnerability`), que es por dónde empezar.

Cómo escribir una detección nueva, la gramática de condiciones, el análisis de la
compresión previa a la autenticación (`zlib` vs `zlib@openssh.com`, CVE-2026-23943,
STIG V-258002) y la verificación contra las fuentes primarias están en
[`docs/politica-vulnerabilidades.md`](politica-vulnerabilidades.md).

---

## Plugins de detección

Una regla del fichero de políticas *empareja*: un nombre, una ventana de
versiones, el valor de una directiva. Lo que no puede hacer es **calcular** —
dividir un número, restar dos fechas, factorizar un módulo. Para eso están los
plugins: **un fichero `.py`** que se deja en un directorio de plugins y ya se
ejecuta. **Casi todas las comprobaciones de la herramienta son plugins** (doce de
serie, en
`builtin/`); no es un sistema para
terceros con lo importante escondido en otro sitio. Dos garantías, y están
comprobadas por tests:

- **Un plugin no puede cambiar la nota.** Recibe una `ServerView` de lo
  *observado* —banner, algoritmos, claves, configuración—, nunca la nota, el
  grado ni el veredicto, y su resultado se añade al informe *después* de
  calcularla. Así, un plugin ausente, roto o de un tercero no mueve en silencio la
  calificación, que es lo único que un auditor tiene que poder dar por firme.
- **Un plugin no puede tumbar el escaneo.** Lo que lance se captura y se informa
  como un hallazgo que lo nombra; el escaneo sigue.

Cargar código es cargar código, así que los directorios de plugins son
**explícitos** (nunca el directorio de trabajo) y uno escribible por el grupo o
por otros se rechaza, con el `chmod` exacto — la misma regla que aplica sshd con
`StrictModes`. Hay tres tipos (`KIND`): `vulnerability` y `check` corren por
servidor, `fleet` una vez al final (para lo que no es propiedad de un solo
servidor, como una clave de host compartida).

```bash
ssh-crypto-checker --list-plugins                 # qué se cargaría, y desde dónde
ssh-crypto-checker servidor --plugin-dir ./mis-plugins
```

El contrato completo —metadatos, `NEEDS`, qué puede devolver `check`, cómo
probarlo y por qué el modelo de puntuación **no** es un plugin— está en
[`docs/plugins.md`](plugins.md), con una guía por tipo
([check](plugin-check.md), [fleet](plugin-fleet.md),
[vulnerability](plugin-vulnerability.md)).

---

## El fichero de políticas

Es el corazón de la herramienta y **el único sitio donde se decide si un
algoritmo es seguro**: la clasificación, las categorías y su puntuación, los
requisitos de tamaño de clave, los avisos por versión y las etiquetas de las que
dependen Terrapin, *encrypt-then-MAC* y el estado de la compresión. Se distribuye
en [`ssh_crypto_checker/data/algorithms.json`](../../ssh_crypto_checker/data/README.md).

```bash
ssh-crypto-checker --export-policy mi-politica.json   # sacar una copia editable
ssh-crypto-checker --show-policy --config mi-politica.json   # ver qué contiene y cuál se cargó
ssh-crypto-checker --config mi-politica.json servidor.example.com   # usarla
```

Sin `--config`, se usa el primero que exista de: `$SSH_CRYPTO_CHECKER_CONFIG`,
`./ssh-crypto-checker.json`, `~/.config/ssh-crypto-checker/algorithms.json`,
`/etc/ssh-crypto-checker/algorithms.json`, y por último la copia del paquete.
También se aceptan `.toml` (Python 3.11+) y `.yaml` (con PyYAML); el formato de
referencia es JSON. El fichero se valida al cargarlo: una categoría inexistente,
una clase que falte o un JSON mal formado dan un error con la línea y la columna,
no un fallo silencioso.

Los manuales para escribir una política propia, con la estructura completa,
empiezan en [`docs/politicas.md`](politicas.md) y siguen por tema:
[algoritmos y etiquetas](politica-algoritmos.md),
[puntuación](politica-puntuacion.md),
[configuración](politica-configuracion.md),
[vulnerabilidades](politica-vulnerabilidades.md) y
[normativas](politica-normativas.md).

---

## Conformidad con estándares (NIST, FIPS, ENS, PCI DSS, ISO…)

Además de la nota propia, cada servidor se evalúa contra **normas publicadas**,
de forma independiente. Una normativa no es código de esta herramienta: es un
documento que mantiene otra gente y revisa en su propio calendario, así que cada
una vive en **su propio directorio**, **un fichero por edición**, y se
**evalúa**, no se compila:
[`ssh_crypto_checker/data/profiles/`](../../ssh_crypto_checker/data/profiles/README.md).
Cuando el escaneo no ve lo suficiente para juzgar, el resultado es **no evaluado**,
nunca *cumple*: una comprobación que no se pudo ejecutar no se ha superado, se ha
omitido.

Se responden **dos preguntas distintas**. *¿Qué fuerza tiene?* — un nivel en bits
(High ≥192 · Moderate ≥128 · Legacy ≥112 · Inadequate <112, según NIST SP 800-57),
el del algoritmo más débil que el servidor acepta. Y *¿cumple la norma X?* — un
perfil que pasa, falla o queda sin evaluar. El porqué de cada nivel y de cada
perfil está en [`docs/politica-normativas.md`](politica-normativas.md).

Se seleccionan con `--profile <id>` (la edición **en vigor**) o `--profile
<id>@<edición>` para fijar una (repetible, o coma-separado), y se listan con
`--list-profiles`. `--require-profile <id>` es además una **puerta de CI**: sale
con código 1 si algún servidor no cumple. Los **25 perfiles** de serie:

| `--profile` | Autoridad | Qué exige |
|---|---|---|
| `nist-sp-800-131a` | NIST | ≥112 bits, sin firmas SHA-1, sin 3DES |
| `fips-140-3` | NIST | Solo funciones aprobadas FIPS (Annex C + FIPS 186-5 + SP 800-56A r3) |
| `cnsa-1.0` | NSA | P-384/SHA-384 y AES-256-GCM; ningún sshd de serie conforma |
| `cnsa-2.0` | NSA | Solo ML-KEM-1024 y ML-DSA-87, sin respaldo clásico |
| `bsi-tr-02102-4` | BSI (Alemania) | 120 bits; solo los identificadores de las tablas 2-5 |
| `ens` | CCN (España) | 128 bits; solo lo de las tablas 4-4 a 4-7 de CCN-STIC-807 |
| `pci-dss-4` | PCI SSC | *Strong cryptography*: ≥112 bits, RSA ≥2048 |
| `cis-benchmark-ssh` | CIS | Lista negra de algoritmos débiles |
| `disa-stig-*-ssh` (15) | DISA (EE. UU.) | Lista blanca FIPS por plataforma — ver `--list-profiles` |
| `anssi-rgs` | ANSSI (Francia) | Reglas por mecanismo; RSA ≥2048 hasta 2030 |
| `iso-27001-a-8-24` | ISO/IEC | Conformidad con tu propia política |

**Cada regla se remite a una sección o tabla exactas de un documento real**,
citadas en los campos `reference` y `notes` del perfil y, textualmente, en
`docs/estandares/CITATION_MAP.md`. Los
documentos fuente se citan (URL, fecha y SHA-256) en
`docs/estandares/`; no todos permiten
redistribuirse (PCI DSS e ISO/IEC son de pago; NIST es de dominio público; CIS es
CC BY-NC-SA), así que se **citan** y se obtienen de su editor, no se incluyen.

Un `PASS` es triaje, no un certificado: varias normas exigen cosas que ningún
escaneo ve (el ENS pide productos CPSTIC; FIPS 140-3, un módulo validado). Para
el requisito **PCI DSS 12.3.3** —el inventario criptográfico documentado— está
`--format inventory`. Todo ello, con la verificación contra las fuentes primarias
y cómo escribir tu propio perfil, en
[`docs/politica-normativas.md`](politica-normativas.md).

```bash
# Evaluar contra dos perfiles y bloquear el CI si no cumplen
ssh-crypto-checker -f inventario.txt --profile ens,pci-dss-4 --require-profile ens

# Ver los perfiles disponibles y su edición
ssh-crypto-checker --list-profiles
```

---

## Cómo se calcula la nota

**Cada clase puntúa por su algoritmo más débil** —no es un promedio: un servidor
es tan fuerte como el peor cifrado que está dispuesto a negociar—. Las clases se
combinan con sus pesos, unos modificadores suman o restan (KEX no estricto, sin
post-cuántico, clave de host corta, grupo DH pequeño), y el número se convierte en
letra. Luego bajan los **topes**: un algoritmo inseguro fuerza `F`, uno débil topa
en `C`, una clave de host por debajo del mínimo en `D`, una vulnerabilidad alta o
crítica confirmada en `C`, y una crítica **medida** —no deducida de la versión
anunciada— en `F`. El JSON trae un `score_breakdown` que hace cada nota auditable.

El **veredicto** (`secure`/`acceptable`/`weak`/`insecure`) se calcula aparte de la
nota, con una sola regla que las ata: **ningún servidor `weak` puede tener mejor
nota que `C`, ni uno `insecure` mejor que `F`**.

> El sistema completo —los cinco pasos, las siete condiciones de tope, la tabla de
> veredictos y un ejemplo calculado paso a paso— está en
> [`docs/como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md).
## Qué comprueba exactamente

**En la conexión, sin autenticarse:**

- Cadena de identificación y versión del software (y líneas de banner previas).
- Los 10 conjuntos de algoritmos del `SSH_MSG_KEXINIT`, con las direcciones
  cliente→servidor y servidor→cliente por separado (se avisa si difieren).
- Soporte de intercambio de claves estricto (`kex-strict-s-v00@openssh.com`).
- Explotabilidad real por Terrapin: `chacha20-poly1305@openssh.com`, o un
  cifrado CBC junto a un MAC `*-etm@openssh.com`, sin KEX estricto.
- Presencia de métodos híbridos post-cuánticos.

**Completando un intercambio de claves** (se puede omitir con `--no-host-keys`):

- Tipo, tamaño en bits y huella SHA-256 de cada clave de host, en el mismo
  formato que `ssh-keygen -lf`.
- Certificados de host OpenSSH: serie, identificador, principales, ventana de
  validez, tipo y huella de la CA.
- Tamaño del grupo Diffie-Hellman que el servidor elige realmente.

Para ello se implementan X25519, ECDH sobre P-256/384/521 y Diffie-Hellman
sobre los grupos MODP 1 y 14, además de `diffie-hellman-group-exchange-*` (donde
es el propio servidor quien envía el módulo). Se abre una conexión por familia
de clave de host.

**Vulnerabilidades conocidas:** 63 comprobaciones sobre OpenSSH, Dropbear y
libssh. Nueve se observan en la conexión (Terrapin, CBC, Sweet32, Logjam, RC4,
firmas SHA-1, soporte de SSH-1, cifrado `none`, MAC `none`) y el resto se
deducen del banner. Las deducidas por versión se marcan siempre como
orientativas, porque las distribuciones aplican parches sin cambiar el número.
**No afectan a la puntuación** salvo que se ponga
`version_advisories_affect_score` a `true`. Ver
[Vulnerabilidades conocidas](#vulnerabilidades-conocidas).

**Con `--auth-methods` o `--audit-config`:** cuatro reglas solo aplican si una
opción no predeterminada está activa (por ejemplo `GSSAPIAuthentication yes`).
Sin esos datos **no se dan por descartadas**: se informan como *no
determinadas*, diciendo qué opción las resolvería.

---

## Códigos de salida e integración en CI

| Código | Significado |
|---|---|
| `0` | Todo escaneado y nada supera el umbral de `--fail-on` |
| `1` | Hay hallazgos de severidad igual o peor que `--fail-on` |
| `2` | Error de uso, o el fichero de políticas no se pudo cargar |
| `3` | Algún servidor no se pudo escanear |

`--fail-on` acepta `never` (por defecto), `critical`, `high`, `medium`, `low` e
`info`.

```yaml
# .gitlab-ci.yml
auditoria-ssh:
  image: python:3.12-slim
  script:
    - pip install .
    - ssh-crypto-checker -f inventario.txt --format json,html -o informe
                         --fail-on high --quiet
  artifacts:
    when: always
    paths: [informe.json, informe.html]
```

Para tratar también los servidores inalcanzables como fallo, comprueba el
código con `[ $? -eq 0 ]` en lugar de `-le 3`.

---

## Las tres interfaces

La misma auditoría se ofrece de tres formas, con idéntico resultado:

- **CLI** — la línea de órdenes de este manual (`./ssh-crypto-checker`).
- **MCP** — un servidor JSON-RPC 2.0 por *stdio* para agentes, con
  `ssh-crypto-checker-mcp` (o `python -m ssh_crypto_checker.mcp`). Expone la
  herramienta `scan` (que toma el mismo `argv` que la CLI) y
  `help`/`list_profiles`/`list_plugins`.
- **Web** — una interfaz web de un solo escaneo con
  `python -m ssh_crypto_checker.web` (endurecida: cabeceras de seguridad, cola de
  trabajos con techo, y un token opcional). El `docker-compose.yml` la levanta en
  contenedor.

## Interfaz web

Una forma **adicional** de usar la herramienta, no un sustituto: el mismo
escaneo, la misma política y los mismos informes, desde un formulario. Cero
dependencias también aquí (el servidor es `http.server` de la biblioteca
estándar). El informe del escaneo se descarga en **cualquiera de los ocho
formatos**, en el idioma elegido — un escaneo, todos los formatos.

```bash
# En local (por defecto escucha solo en 127.0.0.1)
python3 -m ssh_crypto_checker.web
# → http://127.0.0.1:8417/

# En contenedor, de un tirón (usa docker-compose.yml)
make web-up      # construye y arranca en segundo plano → http://localhost:8417/
make web-logs    # sigue el log
make web-down    # para y limpia
```

**Acceso abierto por defecto (sin token, sin usuarios, sin registro).** Es lo
más cómodo para un despliegue interno: cualquiera que alcance el puerto la usa,
en cualquier interfaz. El token es el **único interruptor** que la cierra —
ponlo y cada petición de `/api` exigirá `X-Auth-Token` (comparación en tiempo
constante):

```bash
# Abierta, en tu LAN interna (lo que hace `make web-up` sin más)
docker compose up -d --build
# equivale a:  python3 -m ssh_crypto_checker.web --host 0.0.0.0

# Cerrada con token
SSH_CRYPTO_CHECKER_WEB_TOKEN=un-secreto make web-up
# o a mano, sin compose:
docker run --rm -p 8417:8417 -e SSH_CRYPTO_CHECKER_WEB_TOKEN=un-token sshcryptochecker-web
```

Escanea lo que el contenedor alcance: publicada sin token es una máquina de
SSRF. Úsala en red interna o detrás de tu proxy con TLS; para exponerla,
además del token pon `SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1` y arranca sin ruta
a tus rangos privados (ver «Seguridad de la web» más abajo).

Lo que en la CLI son opciones de despliegue entra por variables y volúmenes,
no por el formulario (así ningún secreto viaja por el navegador):

```bash
# Política propia (la misma variable que honra la CLI)
docker run --rm -p 8417:8417 \
  -v $PWD/mi-politica.json:/config/algorithms.json:ro \
  -e SSH_CRYPTO_CHECKER_CONFIG=/config/algorithms.json \
  sshcryptochecker-web

# Plugins de detección (equivale a --plugin-dir)
docker run --rm -p 8417:8417 \
  -v $PWD/mis-plugins:/plugins:ro \
  -e SSH_CRYPTO_CHECKER_PLUGIN_DIR=/plugins \
  sshcryptochecker-web
```

El formulario cubre lo que tiene sentido en la web: objetivos e inventario
pegado (con etiquetas y opciones por servidor, como en el fichero), normativas
a evaluar y exigir, familia IP, tiempos y concurrencia, las comprobaciones
remotas no autenticadas (`--auth-methods`, `--sshfp` con sus servidores DNS,
`--login-grace`, `--max-startups`) y la presentación. Se queda en la CLI, a
propósito: `--audit-config` (necesita credenciales, que no pintan nada en un
formulario), `known_hosts`, histórico y comparación (viven en ficheros del
operador) y `--audit-client` (auditaría el contenedor, no tu máquina).

### Seguridad de la web

La capa web está endurecida contra las clases conocidas de ataque, y hay
pruebas que lo fijan (`tests/test_web.py`):

- **Nada de agotamiento de recursos.** Todo lo que un anónimo podría inflar
  tiene tope: tamaño del cuerpo (2 MB), número de objetivos, concurrencia,
  timeout, reintentos, `login-grace`, `max-startups` y los escaneos
  simultáneos (más allá, `503`). Un `Content-Length` gigante se rechaza con
  `413` **sin leerlo**.
- **Cabeceras defensivas** en cada respuesta: `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, una `Content-Security-Policy` estricta y
  `Referrer-Policy: no-referrer`. Los informes se descargan como adjuntos, no
  se renderizan en el origen.
- **El token se compara en tiempo constante** (sin fugas por *timing*), y el
  informe HTML **escapa** todo lo que controla el servidor escaneado — un
  banner hostil no puede inyectar script.

Dos cosas no se arreglan en el código, solo en el **borde del despliegue**:

1. **Escanear hosts arbitrarios es la función de la herramienta.** En una red
  interna de confianza, el modo abierto (arriba) es cómodo y legítimo. Expuesta
  a internet es otra cosa —una máquina de SSRF—: ahí ciérrala con
  `SSH_CRYPTO_CHECKER_WEB_TOKEN`, activa `SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1`
  (rechaza objetivos que resuelvan a direcciones privadas/loopback/reservadas —
  defensa en profundidad) y, para la garantía dura, colócala **sin ruta de red**
  a tus rangos internos (un cortafuegos de salida es lo único infalible; el
  filtro de la app solo lo aproxima, por el *DNS rebinding*).
2. **`http.server` es el servidor básico de la stdlib, no un borde
  endurecido.** Para internet, **detrás de un proxy inverso** que termine TLS,
  limite la tasa y rechace peticiones malformadas.

> En una frase: trátala como herramienta **interna** salvo que hayas puesto
> token/filtro **y** un proxy con TLS delante.

---

## Interfaz MCP

Una **tercera** forma de usar la herramienta, junto a la línea de órdenes y la
web, para que la maneje un **modelo de lenguaje**: un servidor **MCP** (*Model
Context Protocol*). El mismo escaneo y los mismos informes que las otras dos,
hablados por **JSON-RPC 2.0 sobre stdio** —un mensaje JSON por línea, el
transporte stdio de MCP—. Cero dependencias también aquí: solo la biblioteca
estándar, **sin SDK ni framework**.

### Requisitos

**Python 3.9 o superior. Nada más** —igual que la CLI—. El servidor MCP no
necesita red para arrancar, ni credenciales, ni un fichero de configuración
propio: se lanza, habla JSON-RPC por su entrada/salida estándar y hereda el
entorno del cliente que lo arranca (así que puede copiarse a un bastión y
registrarse allí, igual que la CLI).

### Instalación

Dos caminos, según prefieras instalar el paquete o usarlo desde el repositorio.

**a) Instalado (recomendado para configurar un cliente).** `pip install .` deja
**dos** comandos en el `PATH`: la CLI y el servidor MCP. Con el comando en el
`PATH`, la configuración del cliente es solo su nombre.

```bash
pip install .            # dentro del repositorio (o `pipx install .`)
ssh-crypto-checker-mcp --version     # comprueba que quedó instalado
```

> Consejo: `pipx install .` lo instala aislado en su propio entorno y deja los
> comandos en el `PATH` global, que es justo lo que un cliente MCP necesita para
> encontrarlos sin activar ningún *virtualenv*.

**b) Desde el repositorio, sin instalar.** Equivale a lo anterior pero ejecutando
el módulo; hay que decirle a Python dónde está el paquete (con `-m` desde la raíz
del repositorio, o con `PYTHONPATH`):

```bash
cd /ruta/a/sshCryptoChecker
python3 -m ssh_crypto_checker.mcp --version
```

### Configuración en un cliente MCP

El servidor **no se lanza a mano** en un terminal —habla JSON-RPC, no con una
persona—: se **registra su comando** en un cliente MCP, que lo arranca por ti y
le habla el protocolo. La forma canónica, común a casi todos los clientes, es una
entrada bajo `mcpServers`:

```json
{
  "mcpServers": {
    "ssh-crypto-checker": {
      "command": "ssh-crypto-checker-mcp"
    }
  }
}
```

**Claude Desktop.** Edita el fichero `claude_desktop_config.json` (Ajustes →
Developer → Edit Config), añade la entrada de arriba y **reinicia** la aplicación.
Su ubicación:

| Sistema | Ruta |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**Claude Code.** Regístralo con un comando (elige el alcance con `-s`
`local`/`user`/`project`), o deja un `.mcp.json` en la raíz del proyecto con el
mismo bloque `mcpServers`:

```bash
claude mcp add ssh-crypto-checker -- ssh-crypto-checker-mcp
claude mcp list                     # comprueba que aparece y conecta
```

**Otros clientes** (Cursor, VS Code, Zed…). Todos consumen la misma forma
`command`/`args`/`env`; cambia solo dónde vive el fichero (p. ej. `.cursor/mcp.json`
en Cursor). Consulta la documentación del cliente para la ruta exacta.

**Ollama.** Ollama ejecuta modelos en **local**, pero **no es en sí un host
MCP**: no arranca servidores MCP por su cuenta. Para darle esta herramienta, usa
un cliente o puente MCP que además hable con Ollama. El más directo es **mcphost**
(un host MCP de código abierto que funciona con modelos de Ollama): apunta su
configuración al comando del servidor,

```json
{ "mcpServers": { "ssh-crypto-checker": { "command": "ssh-crypto-checker-mcp" } } }
```

y lánzalo con `mcphost -m ollama:llama3.1 --config ese-fichero.json`. Otros
clientes que combinan Ollama con MCP son oterm, LibreChat y Open WebUI.

**Sin instalar (usando el repositorio).** Si prefieres no instalar el paquete,
apunta el cliente a `python3 -m` y dile en qué directorio ejecutarlo:

```json
{
  "mcpServers": {
    "ssh-crypto-checker": {
      "command": "python3",
      "args": ["-m", "ssh_crypto_checker.mcp"],
      "cwd": "/ruta/a/sshCryptoChecker"
    }
  }
}
```

> Si tu cliente no admite `cwd`, usa `"env": { "PYTHONPATH": "/ruta/a/sshCryptoChecker" }`
> en su lugar. Con el paquete **instalado** nada de esto hace falta: basta el
> nombre del comando.

### Comprobar que funciona

Antes de configurar el cliente puedes verificar el servidor a mano: se le pasan
uno o dos mensajes JSON-RPC por la entrada estándar y responde por la salida.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ssh-crypto-checker-mcp
```

Debe imprimir dos líneas JSON: la primera con `serverInfo`
(`ssh-crypto-checker-mcp` y la versión), la segunda con la lista de herramientas.
Si en su lugar ves un error de import, el paquete no está en el `PATH`/`PYTHONPATH`
(revisa la instalación). Ya en el cliente, `scan` con `args: ["servidor.example.com"]`
lanza un escaneo real.

### Por qué no pierde ninguna opción

La paridad con la CLI es **de construcción, no de mantenimiento**: cada llamada a
una herramienta termina ejecutando el mismo `ssh_crypto_checker.cli.main` que
ejecuta el terminal, con su salida capturada. La herramienta `scan` recibe el
propio `argv` de la CLI, así que **todo lo que hace el comando lo hace el MCP** —no
hay un esquema paralelo que alguien tenga que mantener sincronizado.

### Las herramientas que expone

| Herramienta | Qué hace |
|---|---|
| `scan` | Escanea. `args` es el vector de argumentos de la CLI: `["servidor.example.com", "--format", "json"]`. Cualquier opción del comando vale. |
| `help` | La ayuda completa de la CLI (todas las opciones), en el idioma elegido (`lang`). |
| `list_profiles` | Lista los perfiles de conformidad disponibles. |
| `list_plugins` | Lista los plugins de detección que se cargarían. |
| `list_vulnerabilities` | Lista las vulnerabilidades conocidas que comprueba la política. |
| `show_policy` | Muestra la política de puntuación activa: clases, pesos, escala de notas y origen. |

Implementa los métodos MCP `initialize`, `tools/list`, `tools/call` y `ping`.
Los **códigos de salida son información, no fallos**: un escaneo de un servidor
débil sale con código distinto de cero **a propósito**, así que una ejecución
completa nunca se informa como error de herramienta —el código se añade al texto—.
`isError` queda para una llamada que no se pudo hacer (argumentos mal formados) o
una excepción inesperada, que se captura para que **una herramienta no pueda tumbar
el servidor**.

> ⚠️ Un MCP le da a un modelo de lenguaje la capacidad de **lanzar escaneos** —y,
> con `scan` y las sondas de `--auth-methods`/`--max-startups`/`--login-grace` en
> `args`, tráfico más intrusivo—. Rigen los mismos límites legales que en la CLI
> (ver [Limitaciones y notas legales](#limitaciones-y-notas-legales)): escanea solo
> lo que estés autorizado a probar. El servidor MCP **no** abre ningún puerto ni
> escucha en la red (a diferencia de la interfaz web): solo habla por stdio con el
> cliente que lo arranca, así que las variables `SSH_CRYPTO_CHECKER_WEB_*` **no** le
> aplican.

---

## Referencia de opciones

```
Modo interactivo
  -w, --wizard              construir el comando respondiendo preguntas
                            (objetivos, normativas, formatos…) y lanzarlo

Idioma
  --lang {en,es}            idioma del asistente, la ayuda y los informes
                            (por defecto: inglés, o el del locale si es español)

Objetivos y credenciales
  TARGET...                 host, host:puerto, IP, IP:puerto o [IPv6]:puerto
  -f, --file FICHERO        lista de objetivos ('-' para stdin); repetible
  --user NOMBRE             cuenta por defecto
  --auth {none,key,password,any}   modo de autenticación por defecto
  -i, --identity FICHERO    clave privada por defecto
  --password-file FICHERO   leer la contraseña de un fichero
  --password-env VAR        leerla de una variable de entorno
  -p, --port PUERTO         puerto por defecto (22)

Comprobaciones remotas adicionales
  --auth-methods            enumerar métodos de autenticación (deja rastro en el log)
  --sshfp                   contrastar las claves con los registros SSHFP en DNS
  --dns-server ADDR         servidor de nombres para SSHFP (admite addr:puerto)
  --login-grace [SEGUNDOS]  medir LoginGraceTime
  --known-hosts [FICHERO]   contrastar con el registro local
  --max-startups [N]        sondear los huecos de preautenticación
  --audit-config            entrar y auditar la configuración con 'sshd -T'
  --audit-client            auditar el ssh_config de esta máquina con 'ssh -G'
  --all-checks              todas las no intrusivas

Escaneo
  -t, --timeout SEGUNDOS    tiempo máximo por conexión (5.0)
  -c, --concurrency N       objetivos en paralelo (8)
  -r, --retries N           reintentos por objetivo (1)
  --no-host-keys            no obtener las claves de host (más rápido)
  --no-cert-probes          omitir los algoritmos de certificado
  -4 / -6                   forzar IPv4 o IPv6
  --source-ip ADDR          dirección local de origen

Política y plugins
  --config FICHERO          fichero de políticas a usar
  --plugin-dir DIR          cargar plugins de detección de ese directorio (repetible)
  --list-plugins            listar los plugins que se cargarían y salir
  --export-policy FICHERO   escribir una copia editable de la política y salir
  --show-policy             mostrar un resumen de la política cargada y salir
  --list-vulnerabilities    listar las vulnerabilidades comprobadas y salir
  --list-profiles           listar los perfiles de conformidad y salir

Salida
  --format FMT              console, json, txt, html, csv, sarif, inventory,
                            openmetrics (repetible o con comas)
  -o, --output RUTA         fichero de salida; añade la extensión del formato si
                            la ruta no la tiene ya (nombre base con varios formatos)
  --color {auto,always,never} / --no-color
  -s, --summary-only        solo la tabla resumen
  --notes                   incluir la explicación de cada algoritmo
  --no-config-suggestions   omitir el sshd_config generado
  -q, --quiet / -v, --verbose

Comparación e histórico
  --compare FICHERO         comparar con un informe JSON anterior (o un histórico)
  --fail-on-regression      salir con código 1 si algún servidor empeoró
  --history FICHERO         añadir este escaneo a un histórico (una línea por escaneo)
  --history-report          mostrar cómo ha ido el parque en los escaneos guardados

Conformidad con normativas
  --profile ID              evaluar solo estos perfiles en vez de todos
                            (repetible o con comas; ID o ID@edición)
  --require-profile ID      salir con código 1 si algún objetivo no cumple ese
                            perfil (repetible o con comas)

Comportamiento
  --fail-on {never,critical,high,medium,low,info}
```

---

## Recetario: un ejemplo por opción

Todo lo que sigue es copiable tal cual. Está ordenado por lo que quieres
conseguir, no por el orden del `--help`.

### La forma más fácil: el asistente

Si no te quieres aprender las opciones, el asistente las pregunta una a una
—objetivos, **credenciales y clave** (`-i`, modo de autenticación, contraseña),
normativas a **evaluar** y a **exigir** (estas solo de entre las evaluadas),
formatos, comprobaciones remotas, presentación, escaneo, **conexión** (bastión,
IP de origen, IPv4/IPv6), política y plugins, e histórico/comparación—,
**muestra el comando** que ha construido y ofrece lanzarlo. Ese comando es
copiable: guárdalo y vuelve a lanzarlo luego sin el asistente.

```bash
# Modo interactivo                                 # --wizard
ssh-crypto-checker --wizard
ssh-crypto-checker -w                              # -w, atajo de --wizard

# En español (el asistente, la ayuda y los informes)   # --lang
ssh-crypto-checker --wizard --lang es
ssh-crypto-checker servidor.example.com --lang en      # forzar inglés
```

El asistente, la ayuda (`--help`) y todos los informes salen en el idioma que
pidas con `--lang {en,es}`. Por defecto es inglés; si tu locale es español
(`LANG`/`LC_ALL` empieza por `es`), se pone en español sin que digas nada.
`--lang` manda siempre sobre el locale. El comando que construye el asistente
termina en `--lang`, para que copiado a otra máquina produzca el mismo informe.
Los formatos legibles por máquina (json, sarif, csv, openmetrics) conservan sus
claves y valores en inglés sea cual sea el idioma: son un contrato para
herramientas, no prosa para personas. Las palabras del armazón de `argparse`
(`usage:`, `options:` y sus mensajes de error de sintaxis) también quedan en
inglés: Python no trae su traducción, y parchear la biblioteca para suplirla se
descartó a propósito.

### Elegir a quién escanear

```bash
# Un servidor en el puerto 22
ssh-crypto-checker servidor.example.com

# Puerto explícito, de tres formas equivalentes
ssh-crypto-checker servidor.example.com:2222
ssh-crypto-checker servidor.example.com -p 2222          # -p, --port
ssh-crypto-checker servidor.example.com --port 2222
ssh-crypto-checker 192.0.2.10:2222

# IPv6: entre corchetes si lleva puerto
ssh-crypto-checker '[2001:db8::1]:22'

# Varios a la vez
ssh-crypto-checker web01 web02 db01.example.com:2222

# Desde un fichero de inventario           # -f, --file
ssh-crypto-checker -f inventario.txt
ssh-crypto-checker --file inventario.txt

# Desde la salida de otro comando
grep -h '^Host ' ~/.ssh/config | awk '{print $2}' | ssh-crypto-checker -f -

# Varios inventarios
ssh-crypto-checker -f produccion.txt -f preproduccion.txt
```

### Credenciales (solo hacen falta para `--audit-config`)

```bash
# Cuenta por defecto para todos los objetivos     # --user
ssh-crypto-checker -f inventario.txt --audit-config --user auditor

# Con clave                                       # --auth, -i/--identity
ssh-crypto-checker servidor --audit-config --auth key -i ~/.ssh/auditor
ssh-crypto-checker servidor --audit-config --auth key --identity ~/.ssh/auditor

# Con contraseña desde una variable de entorno    # --password-env
export AUDIT_PW='...'
ssh-crypto-checker servidor --audit-config --auth password --password-env AUDIT_PW

# Con contraseña desde un fichero                 # --password-file
ssh-crypto-checker servidor --audit-config --auth password --password-file ~/.audit-pw

# Anónimo explícito: no intentes autenticarte     # --auth none
ssh-crypto-checker servidor --auth none --auth-methods
```

> Nunca se admite una contraseña literal en la línea de comandos ni en el
> inventario: quedaría en el historial del shell y en `ps`.

### Ajustar el escaneo

```bash
# Más paciencia con enlaces lentos                # -t, --timeout
ssh-crypto-checker -f inventario.txt -t 15
ssh-crypto-checker -f inventario.txt --timeout 15

# Más objetivos en paralelo (por defecto 8)       # -c, --concurrency
ssh-crypto-checker -f inventario.txt -c 32
ssh-crypto-checker -f inventario.txt --concurrency 32

# Reintentar los que fallen                       # -r, --retries
ssh-crypto-checker -f inventario.txt -r 3
ssh-crypto-checker -f inventario.txt --retries 3

# Más rápido: no obtener las claves de host       # --no-host-keys
ssh-crypto-checker -f inventario.txt --no-host-keys

# No sondear algoritmos de certificado            # --no-cert-probes
ssh-crypto-checker -f inventario.txt --no-cert-probes

# Forzar familia de direcciones                   # -4/--ipv4, -6/--ipv6
ssh-crypto-checker servidor.example.com -4
ssh-crypto-checker servidor.example.com --ipv4
ssh-crypto-checker servidor.example.com -6
ssh-crypto-checker servidor.example.com --ipv6

# Salir por una interfaz concreta                 # --source-ip
ssh-crypto-checker -f inventario.txt --source-ip 10.0.0.5
```

### Redes segmentadas

```bash
# A través de un bastión ya descrito en ~/.ssh/config   # -J, --jump-host
ssh-crypto-checker -f interna.txt -J bastion
ssh-crypto-checker -f interna.txt --jump-host bastion

# Bastión completo en la línea de comandos
ssh-crypto-checker servidor.interno -J ops@bastion.example.com:2222

# Bastión que necesita una clave concreta               # --jump-option
ssh-crypto-checker servidor.interno -J bastion \
    --jump-option=-oIdentityFile=~/.ssh/bastion
```

### Comprobaciones adicionales

```bash
# Métodos de autenticación aceptados              # --auth-methods
ssh-crypto-checker servidor --auth-methods

# Registros SSHFP en DNS                          # --sshfp
ssh-crypto-checker servidor.example.com --sshfp

# ...contra un servidor de nombres concreto       # --dns-server
ssh-crypto-checker servidor.example.com --sshfp --dns-server 10.0.0.53
ssh-crypto-checker servidor.example.com --sshfp --dns-server '[::1]:5353'

# Contrastar con el known_hosts local             # --known-hosts
ssh-crypto-checker -f inventario.txt --known-hosts
ssh-crypto-checker -f inventario.txt --known-hosts /etc/ssh/ssh_known_hosts

# Medir LoginGraceTime (espera hasta 130 s)       # --login-grace
ssh-crypto-checker servidor --login-grace
ssh-crypto-checker servidor --login-grace 60      # esperar solo 60 s

# Sondear MaxStartups (intrusivo: ocupa huecos)   # --max-startups
ssh-crypto-checker servidor --max-startups
ssh-crypto-checker servidor --max-startups 40     # hasta 40 conexiones

# Auditar la configuración entrando por SSH       # --audit-config
ssh-crypto-checker servidor --audit-config --user auditor -i ~/.ssh/auditor

# Auditar el ssh_config de esta máquina           # --audit-client
ssh-crypto-checker servidor --audit-client

# Auditar un ssh_config antes de desplegarlo      # --client-config
ssh-crypto-checker servidor --client-config ./ssh_config.nuevo

# Todo lo no intrusivo de una vez                 # --all-checks
ssh-crypto-checker -f inventario.txt --all-checks
```

> `--all-checks` incluye `--auth-methods`, `--sshfp`, `--known-hosts`,
> `--audit-client` y `--login-grace`. **No** incluye `--max-startups`, que
> ocupa huecos de preautenticación del servidor, ni `--audit-config`, que
> necesita credenciales.

### Formatos de salida

```bash
# A pantalla (por defecto)
ssh-crypto-checker servidor

# Un formato: la extensión se añade si falta          # --format, -o/--output
ssh-crypto-checker servidor --format html -o informe        # -> informe.html
ssh-crypto-checker servidor --format json --output informe.json  # ya la tiene

# Varios: -o es el nombre base y cada uno añade su extensión
ssh-crypto-checker -f inventario.txt --format json,html,csv -o informes/agosto
# -> informes/agosto.json, .html, .csv

# Para el textfile collector de node_exporter
ssh-crypto-checker -f inventario.txt --format openmetrics \
    -o /var/lib/node_exporter/ssh.prom

# Evidencia de inventario criptográfico (PCI DSS 12.3.3)
ssh-crypto-checker -f inventario.txt --format inventory -o inventario-cripto.md

# Para GitHub code scanning
ssh-crypto-checker -f inventario.txt --format sarif -o ssh.sarif.json

# Solo la tabla resumen                           # -s, --summary-only
ssh-crypto-checker -f inventario.txt -s
ssh-crypto-checker -f inventario.txt --summary-only

# Con la explicación de cada algoritmo            # --notes
ssh-crypto-checker servidor --notes

# Sin el sshd_config sugerido                     # --no-config-suggestions
ssh-crypto-checker servidor --no-config-suggestions

# Color                                           # --color, --no-color
ssh-crypto-checker servidor --color always | less -R
ssh-crypto-checker servidor --no-color

# Menos ruido / más ruido                         # -q/--quiet, -v/--verbose
ssh-crypto-checker -f inventario.txt -q
ssh-crypto-checker -f inventario.txt --quiet
ssh-crypto-checker servidor -v
ssh-crypto-checker servidor --verbose
```

### Política y plugins

```bash
# Usar otra política                              # --config
ssh-crypto-checker -f inventario.txt --config politica-corporativa.json

# Sacar una copia editable de la que se usa       # --export-policy
ssh-crypto-checker --export-policy mi-politica.json

# Ver qué política está cargada                   # --show-policy
ssh-crypto-checker --show-policy

# Versión de la herramienta                        # --version
ssh-crypto-checker --version

# Listar lo que se comprueba                      # --list-*
ssh-crypto-checker --list-vulnerabilities
ssh-crypto-checker --list-profiles
ssh-crypto-checker --list-plugins

# Cargar plugins propios                          # --plugin-dir
ssh-crypto-checker servidor --plugin-dir ./mis-plugins
SSHCC_PLUGIN_DIR=~/plugins-ssh ssh-crypto-checker servidor
```

### Conformidad

```bash
# Todas las normativas (por defecto, sin --profile)
ssh-crypto-checker servidor.example.com

# Evaluar solo los perfiles que te importan       # --profile
ssh-crypto-checker -f inventario.txt --profile ens,pci-dss-4

# Una edición concreta de una norma               # --profile ID@edición
ssh-crypto-checker servidor --profile bsi-tr-02102-4@2026-01

# El STIG de tu plataforma (ver --list-profiles para los 15)
ssh-crypto-checker servidor --profile disa-stig-rhel-9-ssh

# Fallar si alguno no conforma                    # --require-profile
ssh-crypto-checker -f inventario.txt --require-profile pci-dss-4

# Exigir conformidad Y no tolerar hallazgos altos (puertas independientes)
ssh-crypto-checker -f inventario.txt --require-profile pci-dss-4 --fail-on high
```

### Histórico y comparación

```bash
# Acumular cada escaneo                           # --history
ssh-crypto-checker -f inventario.txt --history historico.jsonl

# Ver cómo ha ido el parque                       # --history-report
ssh-crypto-checker -f inventario.txt --history historico.jsonl --history-report

# Comparar con un informe anterior                # --compare
ssh-crypto-checker -f inventario.txt --compare base.json

# ...o con la última entrada del histórico
ssh-crypto-checker -f inventario.txt --compare historico.jsonl

# Fallar si algo empeoró, aunque siga cumpliendo  # --fail-on-regression
ssh-crypto-checker -f inventario.txt --compare historico.jsonl --fail-on-regression
```

### Código de salida en CI

```bash
# Fallar con hallazgos de severidad alta o peor   # --fail-on
ssh-crypto-checker -f inventario.txt --fail-on high

# Nunca fallar por hallazgos (por defecto)
ssh-crypto-checker -f inventario.txt --fail-on never
```

### Recetas completas

```bash
# Auditoría diaria en CI, con histórico y detección de regresiones
ssh-crypto-checker -f inventario.txt --all-checks \
    --history /var/lib/sshcc/historico.jsonl \
    --compare /var/lib/sshcc/historico.jsonl --fail-on-regression \
    --format json,html -o informes/$(date +%F) --fail-on high --quiet

# Auditoría profunda de un servidor, con acceso
ssh-crypto-checker servidor.example.com --all-checks --audit-config \
    --user auditor -i ~/.ssh/auditor --max-startups --notes

# Un parque entero tras un bastión, exportando métricas
ssh-crypto-checker -f interna.txt -J bastion --all-checks -c 24 \
    --format openmetrics -o /var/lib/node_exporter/ssh.prom

# Evidencia para una auditoría PCI DSS
ssh-crypto-checker -f inventario.txt --profile pci-dss-4 \
    --format inventory,html -o evidencia/$(date +%F)

# Comprobar un ssh_config antes de desplegarlo
ssh-crypto-checker servidor.example.com --client-config ./ssh_config.nuevo -s
```

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Todo escaneado y nada supera `--fail-on` |
| `1` | Hay hallazgos en o por encima de `--fail-on`, un perfil exigido no se cumple, o hubo una regresión con `--fail-on-regression` |
| `2` | Error de uso, o la política o el histórico no se pudieron cargar |
| `3` | Algún servidor no se pudo escanear |

```bash
ssh-crypto-checker -f inventario.txt --fail-on high
case $? in
    0) echo "todo en orden" ;;
    1) echo "hay hallazgos que atender" ;;
    2) echo "error de uso" ;;
    3) echo "algún servidor no respondió" ;;
esac
```

---

## Auditoría autenticada de la configuración

Todo lo anterior se ve desde la red. **La mayoría de las malas configuraciones
reales, no.** `--audit-config` entra en el servidor con las credenciales del
inventario y lee su configuración efectiva —lo que `sshd -T` resuelve de verdad,
no el fichero—, delegando la conexión en el cliente `ssh` del sistema (la
contraseña, si la hay, va por `SSH_ASKPASS`, nunca a disco). La cuenta necesita
ser root o tener sudo sin contraseña para `sshd`.

```bash
ssh-crypto-checker -f inventario.txt --audit-config
```

Además de dieciséis directivas (`PermitRootLogin`, `PasswordAuthentication`, los
reenvíos…), inspecciona lo que ninguna directiva captura: permisos y propietario
de las claves de host y del `sshd_config`, las `authorized_keys` de **todas** las
cuentas (entradas caducadas, sin caducidad, claves cortas o de tipo obsoleto),
las claves privadas de usuario, `/etc/ssh/moduli`, el paquete de la distribución
(su changelog zanja los avisos por versión) y los bloques `Match` resueltos con
contexto. `--audit-client` hace lo propio con el `ssh_config` de esta máquina.

Las dos decisiones de diseño, la lista completa de lo que inspecciona y cómo
añadir una comprobación (son datos, con la gramática `expect`) están en
[`docs/politica-configuracion.md`](politica-configuracion.md).

---

## Limitaciones y notas legales

- **Escanea solo servidores propios o con autorización expresa.** La conexión
  es inofensiva, pero sigue siendo una conexión no solicitada.
- **Deja rastro en los logs.** Cada objetivo genera al menos una entrada del
  tipo `Connection closed by <ip> port <n> [preauth]`, más una por cada familia
  de clave de host. Con `--no-host-keys` se reduce a una sola.
- **Solo SSHv2.** SSHv1 está obsoleto y se rechaza con un mensaje explícito.
- **No comprueba lo que no se ve desde fuera.** Métodos de autenticación,
  `PermitRootLogin`, `AllowUsers`, versiones parcheadas… no son visibles antes
  de autenticar. Esto complementa, no sustituye, la revisión del `sshd_config`.
- **Los avisos por versión son orientativos.** Debian, Red Hat y compañía
  aplican parches sin cambiar el número de versión anunciado.
- **Las primitivas de `crypto/` no son de tiempo constante** y solo sirven para
  generar una clave efímera de usar y tirar. No las reutilices para proteger
  tráfico real; el aviso está en el docstring del paquete.

---

---

## Licencia

MIT. Ver [LICENSE](../../LICENSE).

## Guías de extensión incluidas

El índice de las guías de extensión es [`extender.md`](extender.md); estas son, instaladas junto a este manual:

- [`auditoria-integridad.md`](auditoria-integridad.md)
- [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
- [`desarrollo.md`](desarrollo.md)
- [`plugin-check.md`](plugin-check.md)
- [`plugin-fleet.md`](plugin-fleet.md)
- [`plugin-vulnerability.md`](plugin-vulnerability.md)
- [`plugins.md`](plugins.md)
- [`politica-algoritmos.md`](politica-algoritmos.md)
- [`politica-configuracion.md`](politica-configuracion.md)
- [`politica-normativas.md`](politica-normativas.md)
- [`politica-puntuacion.md`](politica-puntuacion.md)
- [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md)
- [`politicas.md`](politicas.md)
- [`uso-avanzado.md`](uso-avanzado.md)
