# Manual de política — normativas (perfiles de conformidad)

> Antes de esto, lee [`politicas.md`](politicas.md).

Una normativa se escribe como un fichero JSON dentro de
`data/profiles/<identificador>/<edición>.json`. Sirve tanto para codificar una
norma publicada como para escribir **la política interna de tu organización** y
medir el parque contra ella.

Además de la nota propia, cada servidor se evalúa contra estas normas **de forma
independiente**, y se responden **dos preguntas distintas** que conviene no
mezclar: *¿qué fuerza tiene?* (un nivel según NIST) y *¿cumple la norma X?* (un
perfil que pasa o falla).

---

## La estructura: un directorio por norma, un fichero por edición

```
data/profiles/
  bsi-tr-02102-4/
    2026-01.json
  mi-empresa/
    2026.json
    2025.json
```

- **El directorio es el identificador**: `--profile mi-empresa`.
- **El fichero es la edición**: `--profile mi-empresa@2025`.
- Un nombre a secas significa **la edición en vigor**. Un `nombre@edición`
  significa esa. Son dos preguntas distintas —«¿pasa BSI?» y «¿pasa la edición
  bajo la que nos auditaron?»— y las dos se hacen.
- Con más de una edición, **exactamente una** debe llevar `"current": true`.
  Si ninguna o si varias lo hacen, el cargador se niega, porque cuál rige hoy
  es justo lo que una herramienta de conformidad no debe adivinar.

El nombre del fichero es el selector, así que tiene que ser tecleable:
minúsculas, dígitos, puntos y guiones. `Edición de 2025.json` se rechaza.

Esto existe porque una norma **la mantiene otro y la revisa en su calendario**:
BSI publica TR-02102-4 cada enero, CIS versiona sus benchmarks por distribución,
CNSA pasó de 1.0 a 2.0. Añadir la del año que viene es añadir un fichero; la del
año pasado se queda donde está y se sigue pudiendo medir contra ella.

**Tres cosas que a propósito *no* se hicieron:**

- **Las vulnerabilidades y los algoritmos siguen en `algorithms.json`.** Son el
  modelo de esta herramienta, no documentos ajenos con ediciones. Ocupaban el
  69 % del fichero antes de separar los perfiles (que eran el 15 %), así que si
  el criterio fuera «el fichero es grande» habría que haber empezado por ellos;
  el criterio es otro.
- **`cis-benchmark-ssh` no se partió en seis.** Su edición cita seis benchmarks
  (Ubuntu 22.04 y 24.04, Debian 11 y 12, RHEL 8 y 9) porque **los seis comparten
  el mismo cuerpo de reglas**. Un fichero por edición, no por documento citado.
- **No se inventó ninguna edición histórica.** La estructura admite varias;
  codificar la BSI de 2024 exige leer ese texto. Rellenarlo a ojo sería lo mismo
  que inflar `algorithms.json` con vulnerabilidades inventadas.

> **Dos cosas viajan juntas.** Una política exportada con `--export-policy` se
> lleva su directorio `profiles/` al lado, porque un fichero de política sin
> normativas **no da error**: se parece exactamente a un escaneo contra
> normativas que todo el mundo cumple. Y `pyproject.toml` declara
> `data/profiles/*/*.json` además de `data/*.json`, porque el primer patrón no
> alcanza subdirectorios y un *wheel* se habría quedado sin ellas — también en
> silencio. `tests/test_packaging.py` exige que todo fichero bajo `data/` esté
> cubierto por algún patrón. Exportar una segunda política al mismo directorio
> **está permitido** (un sitio con una política estricta y otra laxa comparte un
> solo juego de normativas); lo que se rechaza es sobrescribir una normativa que
> **dice otra cosa**, y el rechazo ocurre *antes* de escribir nada: media
> exportación es peor que ninguna.

---

## Los niveles de fuerza (NIST SP 800-57)

La primera pregunta —*¿qué fuerza tiene?*— se responde como **fuerza de
seguridad efectiva en bits**, según **NIST SP 800-57 Part 1 Rev. 5, Tabla 2**.
Es la del algoritmo más débil que el servidor acepta, porque es el que un
atacante puede negociar.

| Nivel | Bits | Significado |
|---|---|---|
| **High** | ≥ 192 | Confidencialidad a décadas vista. Es lo que exige CNSA 2.0. |
| **Moderate** | ≥ 128 | El objetivo general de NIST y BSI para sistemas nuevos. Sin fecha de caducidad prevista. |
| **Legacy** | ≥ 112 | Aceptable según NIST SP 800-131A **solo hasta finales de 2030**. Planifica la migración. |
| **Inadequate** | < 112 | Prohibido por NIST SP 800-131A. |

El informe indica además **qué algoritmos concretos** están frenando el nivel,
para que el dato sea accionable:

```
Strength      128-bit — Moderate
  Effective security strength 128 bits (Moderate): ... Held down by
  mlkem768x25519-sha256 (key exchange), curve25519-sha256 (key exchange).
```

Para las claves de host RSA y DSA la fuerza sale del **tamaño real de la clave**
obtenida (2048→112, 3072→128, 7680→192, 15360→256 bits), no del nombre del
algoritmo. Los nombres de las bandas (high/moderate/legacy) son presentación
nuestra; los umbrales en bits son los de NIST.

> Estos niveles son **bandas de fuerza criptográfica de NIST**. No son los
> niveles de impacto Bajo/Moderado/Alto de **FIPS 199**: esos clasifican un
> *sistema* por las consecuencias de su compromiso, algo que ningún escaneo de
> red puede determinar.

---

## Los dos tipos

### `algorithm-strength` — la norma dice qué algoritmos valen

El caso normal. Nueve de las diez que trae la herramienta son así.

```json
{
  "name": "Política criptográfica de Acme",
  "authority": "Seguridad de la Información, Acme S.A.",
  "kind": "algorithm-strength",
  "edition": "v3, aprobada en el comité del 2026-02-11",
  "reference": "Documento SEC-014 v3, sección 4.2 (tabla de algoritmos SSH).",
  "url": "https://intranet.acme.example/sec-014",
  "summary": "Lo que Acme exige a cualquier servidor SSH accesible desde la red corporativa.",
  "current": true,
  "minimum_security_strength": 128,
  "minimum_key_bits": { "rsa": 3072, "ecdsa": 256, "ed25519": 256 },
  "require_strict_kex": true,
  "require_post_quantum": false,
  "algorithms": {
    "kex": {
      "allow": ["curve25519-sha256", "mlkem768x25519-sha256"],
      "reason": "Solo curvas modernas y el híbrido post-cuántico."
    },
    "cipher": {
      "disallow": ["3des-cbc", "aes128-cbc", "aes256-cbc"],
      "reason": "Nada en modo CBC."
    }
  }
}
```

| Campo | Obligatorio | Qué hace |
|---|---|---|
| `name` | **sí** | Cómo se llama en el informe. |
| `authority` | no | Quién la publica. |
| `kind` | no (`algorithm-strength`) | El tipo. |
| `edition` | no | **Ponlo.** Una afirmación de conformidad sin decir contra qué versión se comprobó no vale nada. |
| `reference` | no | De dónde salen las listas, con detalle suficiente para comprobarlo. |
| `url`, `summary`, `notes` | no | Contexto. `notes` deja constancia de **dónde nuestra lectura extiende la norma** (p. ej. aceptar las grafías `@openssh.com`/`-etm` cuando la norma solo nombra identificadores RFC). |
| `current` | no | Si es la edición en vigor. Con una sola edición se sobreentiende. |
| `minimum_security_strength` | no | Bits efectivos mínimos. |
| `minimum_key_bits` | no | Por familia de clave. |
| `require_strict_kex` | no | Exigir que el servidor negocie intercambio estricto de claves. |
| `require_post_quantum` | no | Exigir intercambio post-cuántico. |
| `algorithms` | no | Por clase: `allow`, `disallow`, `disallow_unless_strict_kex` y `reason`. Las listas admiten comodines. |

**`allow` y `disallow` son formas distintas de pensar:**

- `allow` es una **lista blanca**: cualquier cosa que el servidor ofrezca y no
  esté en ella incumple. Es lo que hacen las normas estrictas (FIPS, CNSA).
- `disallow` es una **lista negra**: solo incumple lo nombrado. Es lo que hace
  el benchmark de CIS.

No es lo mismo, y elegir mal produce una norma que aprueba lo que no debería.
Si tu documento dice «solo se permite…», es `allow`.

`disallow_unless_strict_kex` es para lo que una norma excluye **solo mientras**
no haya intercambio estricto de claves. La razón la pone tu `reason`, y es la
que sale impresa: la herramienta no escribe una motivación por ti.

### `policy-conformance` — la norma dice «ten una política y cúmplela»

Algunas normas no listan algoritmos: exigen que la organización defina los
suyos. ISO/IEC 27001 A.8.24 es literalmente eso.

```json
{
  "name": "ISO/IEC 27001:2022 A.8.24",
  "authority": "ISO/IEC",
  "kind": "policy-conformance",
  "reference": "ISO/IEC 27001:2022 Annex A control 8.24 …",
  "forbid_local_categories": ["insecure", "weak"]
}
```

En vez de una lista propia, mide al servidor **contra el fichero de política**:
`forbid_local_categories` dice qué categorías locales constituyen un
incumplimiento. Es el único perfil que cambia de significado cuando editas
`algorithms.json`, y eso es exactamente lo que la norma pide.

#### Sobre ISO: qué se puede y qué no se puede afirmar

**ISO/IEC 27001:2022 no define niveles de fuerza criptográfica.** Su control
A.8.24 «Use of cryptography» exige que la organización *defina e implante*
reglas para el uso de criptografía, pero deliberadamente no nombra algoritmos ni
establece niveles alto/medio/bajo. Tampoco los define ISO/IEC 27002. (ISO/IEC
19790 sí tiene niveles 1–4, pero califican el *módulo* criptográfico
—resistencia física, gestión de roles—, no la elección de algoritmos.)

Por eso la herramienta **no dice «nivel alto según ISO»**: sería inventarlo. Lo
que hace es lo que A.8.24 realmente pide: `iso-27001-a-8-24` comprueba el
servidor **contra este fichero de política**, que *es* el conjunto de reglas
documentado. Un `PASS` es evidencia auditable de que el servidor aplica tu
política criptográfica; no es una certificación ISO, y por sí solo no dice nada
sobre la fuerza: hay que leerlo junto a los perfiles NIST.

```bash
# Evidencia de A.8.24: el parque aplica la política documentada, fechada y reproducible
ssh-crypto-checker -f inventario.txt --require-profile iso-27001-a-8-24 \
                   --format html,json -o evidencia-a824
```

---

## Tres respuestas, no dos

Un perfil puede salir **sin evaluar**, y es una respuesta de pleno derecho:

```
[PASS] ENS (Esquema Nacional de Seguridad)  CCN (Spain)
[FAIL] CNSA 1.0 (transitional suite)        NSA
       - 128-bit effective security strength
[ ?  ] FIPS 140-3 approved algorithms       NIST
       not assessed: this profile requires host keys of a minimum size and no
       host key could be inspected
```

La regla es: **una violación es una prueba y manda sobre todo lo demás**;
encontrarla zanja la cuestión aunque algo más se quedara sin comprobar. Sin
violaciones, solo es un `PASS` si *todos* los requisitos del perfil se llegaron
a probar de verdad.

Suena obvio y no lo era. Hasta esta versión, un perfil que exigía un tamaño
mínimo de clave y no había podido inspeccionar ninguna contestaba `PASS` con una
salvedad en prosa; un aparato propietario que anunciaba nombres que la política
no reconoce salía **conforme con nueve normativas**, porque lo desconocido se
saltaba en vez de juzgarse. Es el mismo fallo contra el que la herramienta avisa
en otro sitio —*«una comprobación que nunca se ejecutó no debe confundirse con
una que salió limpia»*— cometido por ella misma. Ahora ese servidor pasa **cero**.

Lo que puede dejar un perfil sin evaluar:

| Situación | Por qué no es un aprobado |
|---|---|
| Exige tamaño mínimo de clave y no se pudo leer ninguna | Nadie ha mirado la clave |
| Exige una fuerza mínima y la fuerza no se pudo establecer | No hay con qué comparar |
| Exige post-cuántico y el intercambio no se pudo juzgar | «Desconocido» no es «ausente» |
| **Prohíbe** ciertos algoritmos y el servidor ofrece nombres desconocidos | El nombre del fabricante no dice qué hay debajo |
| Mide contra las categorías de tu política y algún algoritmo no tiene ninguna | La pregunta no se puede responder |

La asimetría del cuarto caso es deliberada. Contra una lista **blanca**, un
algoritmo desconocido es una violación demostrable: no estar en una lista cerrada
se decide con el nombre y nada más. Contra una lista **negra** no: que
`vendor-cipher-a@example.com` no aparezca en ella no significa que no sea, por
dentro, uno de los prohibidos.

En OpenMetrics son dos series, para poder distinguirlo al alertar:
`ssh_target_profile_conformance` (1 solo si aprueba) y
`ssh_target_profile_not_assessed`.

---

## Los perfiles no reflejan la nota propia

Un servidor puede fallar la política local y pasar una norma, o al revés. Tres
ejemplos reales que produce la herramienta:

- Un OpenSSH 10 con `mlkem768x25519-sha256` y `chacha20-poly1305@openssh.com`
  saca **A+** aquí y **falla FIPS 140-3**: es criptografía excelente, pero
  ChaCha20-Poly1305 y X25519 no están aprobados por NIST.
- Un servidor FIPS sin KEX estricto ni post-cuántico saca solo una **C** aquí y
  **pasa NIST, FIPS y BSI**.
- `hmac-sha1` **pasa** NIST SP 800-131A —HMAC no depende de la resistencia a
  colisiones, y la norma lo sigue aceptando— aunque esta política lo califica de
  `weak`. El perfil refleja la norma, no la opinión local.

---

## Verificación contra las fuentes primarias

Los perfiles se han contrastado con los documentos publicados, no con el recuerdo
de ellos. Merece la pena conocer estos resultados porque contradicen lo que casi
todo el mundo asume (cada uno con su cita textual en
`estandares/CITATION_MAP.md`):

- **BSI no recomienda `ssh-ed25519` ni ninguna clave RSA para SSH.** La tabla 5
  de TR-02102-4 tiene tres filas y la única entrada práctica es ECDSA sobre
  nistp256/384/521. Tampoco menciona `curve25519-sha256` en ningún sitio.
- **ANSSI recomienda expresamente ChaCha20-Poly1305**, que BSI no recomienda.
  Rechazarlo «en nombre de ANSSI» sería falso.
- **ANSSI no publica ninguna lista `KexAlgorithms` ni `HostKeyAlgorithms`.** Su
  nota de SSH es de 2015 y solo cubre `Ciphers` y `MACs`. Este perfil codifica
  sus reglas por mecanismo, no una configuración inventada.
- **CIS funciona por exclusión.** Un algoritmo que CIS no nombra es conforme. Su
  regex de auditoría es más amplio que la cadena de remediación impresa en la
  misma regla, y excluye `umac-128-etm@openssh.com` pero no `umac-128@openssh.com`.
  **CIS no tiene ninguna regla de `HostKeyAlgorithms`.**
- **CNSA 2.0 no admite ningún respaldo clásico**: *«any algorithm other than
  ML-KEM-1024 MUST NOT be negotiated»*. Ningún SSH actual lo cumple, y el perfil
  lo dice: un fallo mide la brecha de migración, no una mala configuración. Para
  lo alcanzable hoy está `cnsa-1.0`.
- **ANSSI y NSA se contradicen frontalmente en post-cuántico.** ANSSI exige
  hibridación; CNSA 2.0 prohíbe todo lo que no sea ML-KEM-1024 en solitario. Hay
  tests que fijan la contradicción para que no se «resuelva» por accidente.
- **`hmac-sha1` sigue siendo aceptable para NIST SP 800-131A**, porque HMAC no
  depende de la resistencia a colisiones. La política local lo marca `weak`; el
  perfil refleja la norma.
- **El ENS no gradúa los algoritmos de SSH por categoría.** CCN-STIC-807 aplica
  el mismo refuerzo R1 en MEDIA y ALTA, y `mp.com.2`/`mp.com.3` dependen del
  **nivel de la dimensión**, no de la categoría del sistema. Además **128 bits es
  el techo**: el ENS no exige AES-256 ni SHA-512 ni siquiera en ALTA. Hay un
  único perfil `ens`.
- **CCN-STIC-807 §4.2 sí tiene tablas específicas de SSH**, y clasifica cada
  algoritmo como *Recomendado* o *Legacy*. **La ventana Legacy caducó el 31 de
  diciembre de 2025**, así que las claves de host RSA, el grupo 14, CBC y
  `hmac-sha1` ya no están autorizados. Igual que BSI, el ENS deja **solo ECDSA**
  como clave de host: dos normas nacionales escritas por separado llegan a la
  misma conclusión.
- Corrección legal: la medida de protección de claves criptográficas del
  RD 311/2022 es **`op.exp.10`**, no `op.exp.11` — ese era su código en el
  derogado RD 3/2010.

---

## El inventario criptográfico (PCI DSS 12.3.3)

El perfil `pci-dss-4` responde a «¿los algoritmos son suficientemente fuertes?».
El requisito **12.3.3**, obligatorio desde el 31 de marzo de 2025, pide otra
cosa: un **inventario documentado** de las suites y protocolos criptográficos en
uso, revisado al menos una vez al año, con el seguimiento de los algoritmos que
pierden vigencia y una estrategia escrita para sustituirlos.

`--format inventory` produce ese documento en Markdown:

```bash
ssh-crypto-checker -f inventario.txt --format inventory -o inventario-cripto.md
```

Contiene los sistemas en alcance con su implementación, los **excluidos** y por
qué —un servidor que no se pudo escanear es un hueco en la evidencia y se dice
así—, cada algoritmo **una sola vez** con los servidores que lo ofrecen y su
situación bajo la política, los que hay que retirar con el motivo, la posición
ante la criptografía post-cuántica y la estrategia de respuesta.

Ninguna valoración del documento se decide en el código: todas salen del fichero
de políticas. Un inventario de hoy y otro tras la siguiente actualización de la
política se diferencian exactamente en aquello sobre lo que la industria ha
cambiado de opinión, que es la revisión que el requisito pide de verdad.

---

## Escribir la tuya, paso a paso

1. **Crea el directorio** con el identificador que la gente va a teclear:
   `data/profiles/mi-empresa/` — o al lado de tu política exportada, si
   trabajas con `--export-policy`.
2. **Crea el fichero de la edición**: `2026.json`.
3. **Rellena `reference`** con el documento y la sección de verdad. Dentro de
   dos años alguien preguntará de dónde salió cada línea.
4. **Elige `allow` o `disallow`** según lo que diga tu documento.
5. Compruébalo:

```bash
ssh-crypto-checker --config mi-politica.json --list-profiles
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --profile mi-empresa --no-color
```

6. Y para que un escaneo **falle** si alguien no cumple:

```bash
ssh-crypto-checker -f inventario.txt --require-profile mi-empresa --fail-on high
```

`--profile` y `--require-profile` hacen cosas distintas y **se pueden combinar**:
`--profile` *filtra el informe* (solo muestra esos perfiles); `--require-profile`
es *una puerta* (sale con **código 1** si algún servidor no cumple, para bloquear
un despliegue en CI). Las dos son independientes de `--fail-on <severidad>`, que
es la puerta de las **vulnerabilidades/hallazgos**, no de la conformidad.

Un test comprueba que ninguna lista blanca menciona algoritmos que la política
desconoce, de modo que una errata no puede hacer fallar silenciosamente a todos
los servidores. `kind: "policy-conformance"` + `forbid_local_categories` hace un
perfil que se mide contra las categorías de este mismo fichero, como el de ISO.

---

## Dos advertencias

**Los perfiles sirven para triaje, no sustituyen a un auditor.** Varias normas
exigen cosas que ningún escaneo de red puede ver: el ENS en categoría MEDIA y
ALTA requiere **productos certificados del catálogo CPSTIC** (CCN-STIC-105), y
FIPS 140-3 exige un **módulo validado**, no solo algoritmos aprobados. Un `PASS`
aquí es condición necesaria, no suficiente.

**No inventes el contenido de una edición que no has leído.** La estructura
admite varias ediciones; codificar la BSI de 2024 exige leer ese texto.
Rellenarlo a ojo produce un informe de conformidad falso, que es peor que no
tener ninguno.
