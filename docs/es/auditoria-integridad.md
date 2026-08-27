# Auditoría de integridad — ¿todo lo que afirma la herramienta sale de un documento?

**Fecha:** 2026-08-13 · **Alcance:** todo el proyecto (25 perfiles + política base
`algorithms.json`: categorías, fuerzas, vulnerabilidades, comprobaciones de
configuración y puntuación).

**Pregunta que responde:** ¿la herramienta dice que algo está «bien» o «mal» sin
un documento que lo respalde? Es decir, ¿nos hemos inventado algo?

## Método

Tres verificaciones independientes en paralelo, cada una devolviendo **evidencia**
(la línea del documento donde aparece el dato, o «no encontrado»), no un visto
bueno:

1. **15 perfiles DISA STIG** contra los benchmarks CIS/STIG citados.
2. **10 perfiles no-STIG** contra sus documentos (NIST, BSI, ANSSI, ENS, CNSA,
   CIS, ISO, PCI).
3. **Política base** `algorithms.json` contra los documentos presentes en
   `docs/estandares/`.

Más comprobaciones propias sobre la tabla de fuerza, las vulnerabilidades y las
comprobaciones de configuración.

## Veredicto en una frase

**No hay listas inventadas.** Cada perfil traza a su documento. Se encontró **un
único error de comportamiento** (perfil ENS, ya corregido). El problema real no es
que la herramienta mienta, sino que **una parte de sus juicios —correctos— se
apoya en documentos que no están archivados en el repo**, así que hoy no son
*auditables* con el material presente. Y la **puntuación** es metodología propia
que conviene declarar como tal.

---

## 1. Perfiles (25) — trazan a su documento

### DISA STIG (15/15) — VERIFICADO, cero discrepancias
Todas las listas salen del bloque **Audit/Remediation** de la regla citada (no del
«Default Value», que es un ejemplo), ningún algoritmo del JSON falta en el
documento ni al revés, y todos los IDs de regla existen. Cubre: RHEL 8/9/10,
AlmaLinux 9, Amazon Linux 2023, Oracle Linux 7/8, SUSE 15, Ubuntu 20.04/22.04/24.04,
Solaris 11, VMware ESXi 8.0, VMware Photon OS 4.0, macOS 15.

- Matiz de cita (no es fallo): en Solaris el `V-216173` citado es el GROUP ID de la
  edición **X86**; la SPARC usa `V-216410` con la misma regla y lista.

### No-STIG (9 verificados + 1 corregido)
`nist-sp-800-131a`, `fips-140-3`, `cnsa-1.0`, `cnsa-2.0`, `bsi-tr-02102-4`,
`cis-benchmark-ssh`, `iso-27001-a-8-24`, `pci-dss-4` → **VERIFICADO** contra las
tablas/secciones citadas de sus documentos.

**`ens` → ERROR ENCONTRADO Y CORREGIDO.** El perfil omitía
`diffie-hellman-group15-sha512` de su lista kex, pese a que la tabla 4-4 de
CCN-STIC-807 lo marca **Recomendado (R), 128 bits** (RFC 8268, MODP 3072) —cumple
el propio mínimo de 128 bits del perfil—. Peor: el texto de justificación
describía mal el documento («exactamente estas seis… group14 y menores no están»),
cuando la tabla tiene **siete** filas R y la que faltaba era group15. La herramienta
**fallaba incorrectamente** a un servidor que ENS sí permite. Corregido: añadido
`diffie-hellman-group15-sha512` y reescrita la justificación. Verificado contra el
documento (`pdftotext -layout`: fila «group15-sha512 … 128 R»).

### Huecos de documento en perfiles — ✅ CERRADOS
Los tres documentos que un perfil invocaba sin archivar **ya están traídos** (de
libre descarga, con su huella en `estandares/README.md`):
- **`fips-140-3`**: las entradas ML-KEM ya tienen su fuente, **FIPS 203**
  (`NIST.FIPS.203.pdf`). (`SP 800-140Cr2` delega su lista maestra a una URL del
  CMVP, así que FIPS 203 es el documento que hace auditable «ML-KEM aprobado».)
- **`anssi-rgs`**: **DAT-NT-007** (`anssi-dat-nt-007-openssh.pdf`) respalda la
  exclusión de CBC —su **regla R15** manda «AES en mode CTR»— y la retirada de
  DSA; **ANSSI-FT-116** (`anssi-ft-116-transition-pq-sshv2.pdf`, §3.2) respalda el
  rechazo de ML-KEM en solitario a favor de la hibridación. Verificado contra
  ambos PDF.

---

## 2. Política base `algorithms.json`

### Lo que está bien anclado
- **kex y host_key**: sus categorías están sorprendentemente bien respaldadas por
  RFC 9142 + NIST SP 800-131A + FIPS 186-5 + BSI TR-02102-4 + CNSA (todos
  presentes).
- **Tabla de fuerza** (`security_strength.modulus_strength`): coincide exactamente
  con NIST SP 800-57 Part 1 Rev.5 **Table 2** (`[15360,256] [7680,192] [3072,128]
  [2048,112] [1024,80]`), verificado en el PDF.

### El agujero real: cipher y mac (juicios correctos, pero no auditables aquí)
Casi todo lo *weak/insecure* de **cifrado y MAC** se apoya en hechos cuyo
**documento primario no está archivado** en el repo. Los veredictos son correctos;
lo que falta es la fuente que los acredite localmente:

| Hecho invocado | Afecta a | Documento que faltaría |
|---|---|---|
| RC4 roto (sesgo de keystream) | `arcfour`, `arcfour128`, `arcfour256`, patrón `arcfour*`, vuln `RC4-BIAS` | **RFC 7465** (+ rc4nomore) |
| MD5 roto | `hmac-md5*` (4) + patrón `*-md5*` | **RFC 6151** |
| Sweet32 (bloque 64 bits) | `blowfish-*`, `cast128-*`, `idea-cbc`, vuln `CVE-2016-2183` | **CVE-2016-2183** / paper Sweet32 |
| Recuperación de texto plano en CBC de SSH | `aes*-cbc`, `twofish*-cbc`, `serpent256-cbc`, `rijndael-cbc@…`, patrón `*-cbc*`, vuln `CVE-2008-5161` | **CVE-2008-5161 / CERT VU#958563** |
| Terrapin | tag `terrapin-vector`, vuln `CVE-2023-48795` | **CVE-2023-48795** / paper Terrapin |
| Logjam (precomputación) | escalada de `group1-sha1` a insecure, vuln `LOGJAM` | **CVE-2015-4000** / weakdh.org |
| Colisiones SHA-1 prácticas | *rationale* de `ssh-rsa`/`ssh-dss` (la **categoría** insecure sí la respalda SP 800-131A + RFC 9142) | **SHATTERED** |

> Nota: 3DES (`3des-cbc`/`3des-ctr`) **sí** está respaldado: NIST SP 800-131A
> prohíbe 3TDEA tras 2023 (documento presente). Y CIS/STIG recomiendan listas de
> `Ciphers` sin CBC, respaldo parcial de configuración.

### Vulnerabilidades (65) — resuelto por decisión del propietario
- **3 respaldadas por documento del repo**: `NULL-CIPHER` y `NULL-MAC` (RFC 4253
  §6.3/§6.4), `PREAUTH-COMPRESSION` (DISA STIG V-258002, en el RHEL 9 STIG).
- **62 nombran su CVE**: el CVE es una **referencia pública verificable**
  (NVD/MITRE). Decisión del propietario (2026-08-13): **los CVE no se archivan**
  —son públicos—, basta con citarlos. No es un hueco: es la política de
  procedencia para referencias públicas.

### Comprobaciones de configuración (26) — ✅ CORREGIDO
Antes, 23 de 26 no citaban su fuente. Ahora **cada comprobación lleva un campo
`reference`**, y un test (`test_every_config_check_cites_a_source`) lo exige:
- **Servidor (16)**: cada una cita su regla CIS/STIG verificada (p. ej.
  `PermitRootLogin` → CIS «Ensure sshd PermitRootLogin is disabled», RHEL 9 v2.0.0
  regla 5.1.20; el reenvío X11/agente → 5.1.10 DisableForwarding; etc.).
- **Cliente (10)**: `StrictHostKeyChecking`, `ForwardAgent`, `HashKnownHosts`…
  **no** están en los CIS/STIG de servidor del repo; su fuente normativa es el
  manual **`ssh_config(5)` de OpenSSH** (referencia pública, mismo criterio que
  los CVE: se cita, no se archiva).

### Metodología propia de la herramienta — ✅ DECLARADA
No sale de ningún documento —y no debería, es un criterio de diseño legítimo—.
Antes no estaba declarado; ahora **sí**: los bloques `categories` y `scoring` del
fichero de política llevan un `_comment` que dice explícitamente que los números
son criterio propio (no de un documento externo), y
[`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) abre con una sección
«De dónde salen estos números (y de dónde no)» que lo separa del respaldo
documental de las categorías. Afecta a:
- `scoring`: pesos por clase (25/25/20/20/10), modificadores, umbrales de nota
  (A+…F) y topes (`grade_caps`).
- `categories`: los `score` 100/75/35/0 y las severidades.
- `security_strength.levels`: los **umbrales** en bits sí son de NIST, pero los
  **nombres** (high/moderate/legacy/inadequate) y el «required by CNSA 2.0» son
  encuadre propio.
- Categorías «de opinión» más estrictas que el documento: `chacha20-poly1305@openssh.com`
  como *recommended* (BSI TR-02102-4 no lo menciona — 0 apariciones), la familia
  **UMAC**, `hmac-ripemd160*`, los MAC truncados a 96 bits, `rsa2048-sha256`
  degradado a *weak* por falta de forward secrecy, y las entradas sntrup/Kyber
  pre-estándar (ningún documento del repo las cubre).

---

## 3. Acciones — estado

**Hechas en esta auditoría:**
- [x] **Corregido el error de ENS** (`diffie-hellman-group15-sha512`), verificado
  contra el documento.
- [x] **Las 26 comprobaciones de config citan su fuente** (campo `reference`;
  servidor → regla CIS/STIG, cliente → `ssh_config(5)`), con un test que lo exige.
- [x] **La puntuación queda declarada como metodología propia** (`_comment` en
  `categories`/`scoring` + sección nueva en `como-se-calcula-la-nota.md`).
- [x] **CVE**: decisión del propietario — son públicos, se citan y **no se
  archivan**. Igual para los manuales OpenSSH del lado cliente.
- [x] **Documentos que faltaban, ya traídos**: FIPS 203 (`NIST.FIPS.203.pdf`),
  ANSSI DAT-NT-007 y ANSSI-FT-116 están archivados en
  `estandares/`, así que `fips-140-3` y `anssi-rgs`
  se auditan sobre la fuente.

**Sobre cipher/mac (categoría B):** los veredictos son correctos y descansan en
referencias **públicas** (RFC 7465/RC4, RFC 6151/MD5, y los CVE de Sweet32,
Logjam, Terrapin, CBC/SSH, SHA-1/SHATTERED). Por la misma política que los CVE,
esas referencias públicas **se citan, no se archivan**. Cada nota de algoritmo
las nombra; no hay veredicto sin una referencia pública detrás.

**Opcional pendiente:** afinar la cita de Solaris (nombrar la edición SPARC
`V-216410`).

---

## Conclusión

La herramienta **no se inventa nada**: los 25 perfiles trazan a su documento, el
único error real (ENS) está corregido, y todo juicio de la política base tiene
detrás **o un documento que tenemos, o una referencia pública verificable** (CVE,
RFC, manual OpenSSH) que —por decisión de procedencia— se cita pero no se archiva.
La metodología de puntuación, que es criterio propio, queda declarada como tal.
Los tres documentos que faltaban (FIPS 203, DAT-NT-007, ANSSI-FT-116) ya están
archivados en `estandares/`, así que `fips-140-3` y `anssi-rgs` se auditan
sobre la fuente y no de memoria.
