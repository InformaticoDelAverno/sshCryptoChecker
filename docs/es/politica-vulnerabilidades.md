# Manual de política — vulnerabilidades

> Antes de esto, lee [`politicas.md`](politicas.md).

Una vulnerabilidad se escribe entera como un dato en la lista
`vulnerabilities`. No hace falta programar, y por eso es el sitio donde debe
ir todo lo que quepa.

---

## La forma de una entrada

```json
{
  "id": "CVE-2023-48795",
  "name": "Terrapin: truncado de prefijo en el intercambio de claves",
  "severity": "medium",
  "description": "Qué pasa y por qué importa, para quien no lo conoce.",
  "remediation": "Qué hacer exactamente. Un mandato, no un consejo.",
  "references": ["CVE-2023-48795", "https://terrapin-attack.com/"],
  "affects": "server",
  "detection": { ... }
}
```

| Campo | Obligatorio | Notas |
|---|---|---|
| `id` | **sí** | Único. Un duplicado se rechaza al cargar: dos detecciones con el mismo id no se pueden informar las dos. |
| `name` | **sí** | Título del informe. |
| `severity` | **sí** | `critical`, `high`, `medium`, `low`, `info`. |
| `description` | **sí** | Escríbela para quien la va a leer a las dos de la mañana. |
| `remediation` | sí en la práctica | Sin esto, es una queja. |
| `references` | sí en la práctica | **Sin referencia es una opinión.** |
| `affects` | no (`server`) | `server` o `client`. |
| `detection` | **sí** | La condición. Todo lo demás de este manual. |

---

## La gramática de detección

Una condición es un objeto con **una** clave. Hay cinco condiciones que miran
algo y tres que combinan otras.

### `version` — por versión del producto

```json
"detection": {
  "version": {
    "product": "OpenSSH",
    "affected": [ { "introduced": "8.5p1", "fixed": "9.8p1" } ]
  }
}
```

La ventana es **`[introducida, corregida)`**: incluye la primera, excluye la
segunda. Se pueden poner varias ventanas.

> **Esto es una inferencia, no una medición**, y la herramienta lo trata como
> tal: si la auditoría autenticada puede leer el *changelog* del paquete y ve
> que la distribución retroportó el arreglo, el hallazgo baja a informativo.
> Es la diferencia entre «esta versión suele estar afectada» y «este servidor
> lo está».

### `protocol` — por versión del protocolo

```json
"detection": { "protocol": { "versions": ["1.99", "1.5"] } }
```

Un servidor que contesta `SSH-1.99` habla los dos protocolos y está expuesto a
todo lo que tiene mal SSH-1, que ninguna configuración de algoritmos arregla.

### `present` / `absent` — por algoritmo

```json
{ "present": { "class": "compression", "algorithms": ["zlib"] } }
{ "present": { "class": "cipher", "tags": ["cbc"] } }
{ "absent":  { "class": "kex", "algorithms": ["kex-strict-s-v00@openssh.com"] } }
```

`class` es una de las cinco. Se puede filtrar por `algorithms` (nombres
exactos) o por `tags`.

> **Prefiere `tags`.** Una regla sobre la etiqueta `cbc` sigue valiendo cuando
> aparezca un CBC que hoy no existe; una lista de nombres, no.

### `host_key` — por propiedad de la clave

```json
{ "host_key": { "family": "dsa", "below_bits": 2048 } }
```

`family` es `rsa`, `dsa`, `ecdsa`, `ed25519`, `ed448`… y `below_bits` es el
umbral. Las claves que no se pudieron leer se saltan: una clave con error no
es una clave de 0 bits.

### `config` — por directiva

```json
{ "config": { "directive": "permitrootlogin", "equals": "yes" } }
```

Comparadores: `equals`, `in`, `not_in`, `present`, `absent`. Necesita
`--audit-config`; sin él, la detección queda **sin determinar**, que no es lo
mismo que no cumplirse.

### `auth_method` / `extension` — por método de autenticación

```json
{ "auth_method": { "methods": ["password", "keyboard-interactive"] } }
{ "extension": { "names": ["ping@openssh.com"] } }
```

`auth_method` casa si el servidor **ofrece** alguno de esos métodos de
autenticación; `extension`, si anuncia alguna de esas extensiones de RFC 8308.
Las dos necesitan `--auth-methods`; sin él, la detección queda **sin determinar**.

### `all`, `any`, `not` — para combinar

```json
"detection": {
  "all": [
    { "absent": { "class": "kex", "algorithms": ["kex-strict-s-v00@openssh.com"] } },
    { "any": [
        { "present": { "class": "cipher", "tags": ["terrapin-vector"] } },
        { "all": [
            { "present": { "class": "cipher", "tags": ["cbc"] } },
            { "present": { "class": "mac", "tags": ["etm"] } }
        ]}
    ]}
  ]
}
```

Eso es Terrapin de verdad: **sin** la contramedida, **y** (un cifrado de la
familia vulnerable **o** la combinación CBC + ETM). Se anidan sin límite.

---

## Las tres formas de detectarlas

Las 65 entradas se detectan por uno de tres caminos, y la diferencia importa
para leer el informe:

- **En la conexión (10).** Se observa lo que el servidor ofrece de verdad, así
  que no hay margen de error: Terrapin (`CVE-2023-48795`, KEX no estricto con
  cifrado vulnerable), CBC (`CVE-2008-5161`), Sweet32 (`CVE-2016-2183`, bloque de
  64 bits), LOGJAM (DH de 1024 o DSA pequeña), RC4-BIAS (`arcfour*`),
  SHA1-SIGNATURE (`ssh-rsa`/`ssh-dss` de host), SSH1-PROTOCOL (banner `SSH-1.x`),
  PREAUTH-COMPRESSION (`zlib` a secas), NULL-CIPHER y NULL-MAC (`none`).
- **Por versión (54).** El resto se deduce del banner. Estas **siempre** llevan
  la advertencia de que las distribuciones retroportan parches sin cambiar el
  número, así que hay que contrastarlas con el *changelog* del paquete.
- **Condicionadas a la configuración (4).** Solo aplican si una opción no
  predeterminada está activa: `CVE-2026-60000` (DoS por GSSAPI) exige
  `GSSAPIAuthentication yes`, y saberlo requiere `--audit-config`.

> **No mirar no es lo mismo que mirar y no encontrar nada.** Una regla que
> necesita datos que el escaneo no recogió no se evalúa a `false` en silencio: se
> marca como *no determinada* y el informe dice con qué opción se resolvería.
> Informar de un servidor como no afectado porque nadie hizo la pregunta es el
> único modo de fallo que este módulo no puede tener.

---

## La compresión previa a la autenticación

Es la clasificación que más se pregunta, porque las guías se contradicen. Lo que
dicen las fuentes:

| Método | Clasificación | Por qué |
|---|---|---|
| `none` | Recomendado | Evita el canal lateral por completo |
| `zlib@openssh.com` | Recomendado | Solo se activa **tras** autenticar |
| `zlib` | **Inseguro** | Se activa en cuanto acaba el intercambio de claves |

`zlib` empieza a comprimir —y a **descomprimir**— en cuanto termina el
intercambio de claves, o sea antes de que nadie se haya autenticado, en un
proceso que aún no ha soltado privilegios. `zlib@openssh.com` hace lo mismo pero
espera. Y no es teórico:

- **DISA STIG V-258002** lo exige: *«el demonio SSH no debe permitir compresión,
  o solo debe permitirla tras una autenticación correcta»*, porque un fallo en el
  código de compresión sería alcanzable *desde una conexión no autenticada,
  potencialmente con privilegios de root*.
- **CVE-2026-23943** (CVSS 6.9) es exactamente eso: un servidor que anuncia `zlib`
  heredado e infla datos del cliente antes de autenticar sin límite de tamaño.
  256 KB en el cable se convierten en unos 255 MB en memoria —amplificación de
  1029:1— y agotan la memoria del servidor sin credenciales.
- **OpenSSH quitó la compresión previa a la autenticación en 7.4** (2016). Desde
  entonces `Compression yes` significa *diferida*: un OpenSSH moderno **nunca**
  ofrece `zlib` a secas. Si lo ves, es algo más viejo u otra implementación.

**¿Y `zlib@openssh.com`?** El manual de OpenSSH desaconseja la compresión *en
conexiones que mezclan datos de confianza con datos que no lo son*, porque la
longitud comprimida puede filtrar algo del secreto — la forma del ataque CRIME
contra TLS. Es un riesgo **condicional**, y por eso sigue siendo recomendado y no
*acceptable*: degradarlo costaría 2,5 puntos a **cualquier** OpenSSH por defecto,
y como A+ exige 100, ninguno podría sacar A+ jamás. El aviso está en las notas del
algoritmo (`--notes`), donde quien reenvíe datos ajenos lo encontrará.

**Lo que las normativas *no* dicen.** La nota técnica de ANSSI sobre uso seguro de
(Open)SSH **no menciona la compresión** —verificado sobre el documento—, y ni BSI
TR-02102-4 ni ENS entran en el asunto. La única exigencia normativa que existe es
la del STIG, y **permite** la compresión diferida.

Todos los informes llevan una línea **Compression** en la cabecera de cada
servidor, con uno de cuatro estados: `disabled (no compression offered)`,
`enabled, after authentication only`, `enabled BEFORE authentication` (en rojo, con
el motivo) o `unknown`. En los formatos de máquina es el campo `compression` (JSON,
CSV) y el *gauge* OpenMetrics `ssh_target_compression_preauth`. Y no se puede sacar
buena nota con `zlib` puesto: está clasificado `insecure`, y el tope
`any_insecure_algorithm` fuerza la nota a **F** por muy bien que esté lo demás
(90/100 y aun así F) — es lo que le pasa al Dropbear del laboratorio.

---

## Verificación contra las fuentes primarias

Los rangos de versiones no salen de memoria: se contrastaron con
[openssh.com/security.html](https://www.openssh.com/security.html), las notas de
versión de OpenSSH y los registros del *Debian Security Tracker* para openssh,
dropbear y libssh. Un rango mal puesto es peor que no comprobar nada, porque da
una respuesta confiada y equivocada. Dos consecuencias:

- **`CVE-2016-20012`** está **disputada** por el propio proyecto OpenSSH, que la
  considera inherente al método de clave pública. Se incluye porque el registro
  CVE existe y algunas auditorías preguntan por ella, pero la descripción dice que
  está disputada.
- **Un OpenSSH 10.3 recién instalado sale con tres avisos**, porque 10.4 corrigió
  cosas. Es correcto: la nota sigue siendo A+ (los algoritmos son impecables) y los
  avisos por versión no puntúan, pero el informe no oculta que hay parches
  pendientes.

Dos notas de compatibilidad. La detección se **valida al cargar** la política, no
al evaluarla: una condición mal escrita da un error con el identificador de la
vulnerabilidad, en vez de una regla que nunca casa y nadie nota; y si una regla
resulta malformada en tiempo de ejecución, sale como hallazgo informativo en vez
de fallar en silencio hacia «no vulnerable». Hubo un campo `flags` que activaba
un modificador de −20 y un tope de nota para una sola CVE; al quitar ese enganche
quedó imprimiéndose para **una** de las 65 entradas y ninguna otra, así que se
borró: cuánto pesa una vulnerabilidad lo dice su severidad, igual que las otras 64.
Las entradas antiguas de `software_advisories` se siguen aceptando y se convierten
en vulnerabilidades por versión, para que una política escrita antes siga
funcionando.

---

## Escribir una nueva, paso a paso

1. **Busca la referencia primero.** El CVE, el aviso, el commit. Si no la
   encuentras, no la escribas.
2. **Decide qué la detecta de verdad.** ¿Es una ventana de versiones? ¿Es un
   algoritmo ofrecido? ¿Hacen falta las dos cosas? Escribe la condición más
   estrecha que sea correcta: una detección que salta de más se acaba
   ignorando, y entonces también se ignora la que importa.
3. **Escribe `remediation` como una orden.** «Actualiza a 9.8p1 o quita los
   cifrados CBC de la directiva Ciphers», no «considere actualizar».
4. **Pruébala contra el laboratorio**, que tiene servidores con estos defectos
   a propósito:

```bash
ssh-crypto-checker --config mi-politica.json --list-vulnerabilities | grep MI-ID
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2204 --no-color   # CBC sin contramedida
```

5. **Comprueba también que NO salta donde no debe.** Un servidor moderno no
   puede empezar a mostrar tu hallazgo:

```bash
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --no-color   # modern
```

---

## Los tres errores que se cometen

**Detectar por nombre lo que se debería detectar por propiedad.** Si escribes
la lista de los seis cifrados CBC que conoces hoy, tu regla envejece. Usa
`tags`.

**Afirmar como medido lo que solo se dedujo.** Una detección por versión dice
que esa versión suele estar afectada. Si el mecanismo de *changelog* puede
desmentirla, déjale hacerlo: no la conviertas en `critical` con una condición
que no mira el servidor.

**Olvidar la remediación.** Un informe con veinte hallazgos y ninguna
instrucción no cambia nada en ningún servidor.
