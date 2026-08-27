# `data/profiles/` — las normativas

Una normativa no es código de esta herramienta: es **un documento que mantiene
otro y revisa en su propio calendario**. Por eso:

- **El directorio es el identificador** de la norma.
- **El fichero es la edición**, y se pide escribiéndola: `--profile ens@2022-05`.
- Un nombre a secas (`--profile ens`) significa **la edición en vigor**.
- Con más de una edición, exactamente una declara `"current": true`; el
  cargador se niega si ninguna o si varias lo hacen, porque cuál rige hoy es
  justo lo que una herramienta de conformidad no debe adivinar.

Añadir la edición del año que viene es añadir un fichero. La del año pasado se
queda donde está y se sigue pudiendo medir contra ella, que es la pregunta que
una auditoría hace de verdad: no «¿pasa BSI?» sino «¿pasa la edición bajo la
que nos auditaron?».

## Subdirectorios

| Directorio | Norma | Autoridad | Edición codificada | Mínimo |
|---|---|---|---|---|
| [`nist-sp-800-131a/`](nist-sp-800-131a/README.md) | NIST SP 800-131A Rev. 2 | NIST | `rev-2-2019` | 112 bits |
| [`fips-140-3/`](fips-140-3/README.md) | FIPS 140-3, funciones aprobadas | NIST | `annex-c` | 112 bits |
| [`cnsa-1.0/`](cnsa-1.0/README.md) | CNSA 1.0 (suite de transición) | NSA | `2016` | 192 bits |
| [`cnsa-2.0/`](cnsa-2.0/README.md) | CNSA 2.0 | NSA | `draft-02` | 192 bits |
| [`bsi-tr-02102-4/`](bsi-tr-02102-4/README.md) | BSI TR-02102-4 | BSI (Alemania) | `2026-01` | 120 bits |
| [`ens/`](ens/README.md) | ENS (CCN-STIC-807) | CCN (España) | `2022-05` | 128 bits |
| [`pci-dss-4/`](pci-dss-4/README.md) | PCI DSS v4.0 | PCI SSC | `v4-0-1` | 112 bits |
| [`cis-benchmark-ssh/`](cis-benchmark-ssh/README.md) | CIS Benchmark, servidor SSH | CIS | `2025-10` | — (lista negra) |
| [`disa-stig-rhel-9-ssh/`](disa-stig-rhel-9-ssh/README.md) | DISA STIG, servidor SSH (RHEL 9) | DISA (EE. UU.) | `rhel-9-v1.0.0` | — (lista blanca) |
| [`disa-stig-rhel-10-ssh/`](disa-stig-rhel-10-ssh/README.md) | DISA STIG, servidor SSH (RHEL 10) | DISA (EE. UU.) | `rhel-10-v1.0.0` | — (lista blanca) |
| [`disa-stig-rhel-8-ssh/`](disa-stig-rhel-8-ssh/README.md) | DISA STIG, servidor SSH (RHEL 8) | DISA (EE. UU.) | `rhel-8-v2.0.0` | — (lista blanca) |
| [`disa-stig-almalinux-9-ssh/`](disa-stig-almalinux-9-ssh/README.md) | DISA STIG, servidor SSH (AlmaLinux OS 9) | DISA (EE. UU.) | `almalinux-9-v1.0.0` | — (lista blanca) |
| [`disa-stig-amazon-linux-2023-ssh/`](disa-stig-amazon-linux-2023-ssh/README.md) | DISA STIG, servidor SSH (Amazon Linux 2023) | DISA (EE. UU.) | `amazon-linux-2023-v1.0.0` | — (lista blanca) |
| [`disa-stig-oracle-linux-8-ssh/`](disa-stig-oracle-linux-8-ssh/README.md) | DISA STIG, servidor SSH (Oracle Linux 8) | DISA (EE. UU.) | `oracle-linux-8-v1.0.0` | — (lista blanca) |
| [`disa-stig-oracle-linux-7-ssh/`](disa-stig-oracle-linux-7-ssh/README.md) | DISA STIG, servidor SSH (Oracle Linux 7) | DISA (EE. UU.) | `oracle-linux-7-v1.0.0` | — (lista blanca) |
| [`disa-stig-suse-15-ssh/`](disa-stig-suse-15-ssh/README.md) | DISA STIG, servidor SSH (SUSE Linux Enterprise 15) | DISA (EE. UU.) | `suse-15-v1.0.0` | — (lista blanca) |
| [`disa-stig-ubuntu-2004-ssh/`](disa-stig-ubuntu-2004-ssh/README.md) | DISA STIG, servidor SSH (Ubuntu 20.04) | DISA (EE. UU.) | `ubuntu-2004-v2.0.0` | — (lista blanca) |
| [`disa-stig-ubuntu-2204-ssh/`](disa-stig-ubuntu-2204-ssh/README.md) | DISA STIG, servidor SSH (Ubuntu 22.04) | DISA (EE. UU.) | `ubuntu-2204-v1.0.0` | — (lista blanca) |
| [`disa-stig-ubuntu-2404-ssh/`](disa-stig-ubuntu-2404-ssh/README.md) | DISA STIG, servidor SSH (Ubuntu 24.04) | DISA (EE. UU.) | `ubuntu-2404-v1.0.0` | — (lista blanca) |
| [`disa-stig-solaris-11-ssh/`](disa-stig-solaris-11-ssh/README.md) | DISA STIG, servidor SSH (Solaris 11) | DISA (EE. UU.) | `solaris-11-v1.0.0` | — (lista blanca, solo cifrado) |
| [`disa-stig-esxi-ssh/`](disa-stig-esxi-ssh/README.md) | DISA STIG, servidor SSH (VMware ESXi 8.0) | DISA (EE. UU.) | `esxi-8.0-v1.0.0` | — (lista blanca, solo cifrado) |
| [`disa-stig-photon-ssh/`](disa-stig-photon-ssh/README.md) | DISA STIG, servidor SSH (VMware Photon OS 4.0) | DISA (EE. UU.) | `photon-4.0-v1.0.0` | — (lista blanca, cifrado + MAC) |
| [`disa-stig-macos-ssh/`](disa-stig-macos-ssh/README.md) | DISA STIG, servidor SSH (macOS 15) | DISA (EE. UU.) | `macos-15-v1.0.0` | — (lista blanca) |
| [`anssi-rgs/`](anssi-rgs/README.md) | ANSSI, reglas criptográficas | ANSSI (Francia) | `pg-083-v3-00` | — (por mecanismo) |
| [`iso-27001-a-8-24/`](iso-27001-a-8-24/README.md) | ISO/IEC 27001:2022 A.8.24 | ISO/IEC | `2022` | — (tu propia política) |

## Qué hay dentro de un fichero de edición

`name`, `authority`, `edition` y `reference` (de dónde salen las listas, con
suficiente detalle para comprobarlo), `url`, `summary`, `current`, y luego lo
que exige: `minimum_security_strength`, `minimum_key_bits` por familia,
`require_strict_kex`, `require_post_quantum` y `algorithms` con `allow` o
`disallow` por clase. `kind: policy-conformance` mide contra la política local
en vez de contra una lista propia — que es lo que ISO 27001 A.8.24 pide.

## Pendientes (TODO)

Normativas cuyos documentos ya están en `docs/estandares/` pero que aún **no**
tienen perfil, con por qué. Hay dos frenos recurrentes:

1. **Fixture de laboratorio.** El test `test_every_profile_is_seen_both_passing_and_failing`
   exige que algún servidor del laboratorio **pase** cada perfil y otro lo
   **falle**. Un *allowlist* muy estricto que ningún servidor actual cumpla
   necesita un servidor nuevo configurado a esa lista (añadir un servicio a
   `lab/docker-compose.yml`, su `.conf`, `PORTS` en el test,
   `lab/lab-inventory.txt`, `lab/configs/README.md` y **regenerar**
   `tests/lab-coverage-baseline.json`). Exentarlo (`UNREACHABLE_BY_STOCK_SSH`)
   solo es honesto si **ningún** OpenSSH puede cumplirlo, que no es el caso de
   estos.
2. **Lectura por regla.** Varios documentos imprimen la lista de algoritmos
   como *ejemplo de sintaxis* (con algoritmos débiles incluidos) o en varias
   formas por regla; codificar por `grep` suelto llevaría a un perfil que
   miente. Hay que leer la regla mandada en su contexto.

### DISA STIG por plataforma (la política SSH de las STIG varía por plataforma)

- **macOS 15 (Sequoia) STIG** — ✅ **hecho**: perfil [`disa-stig-macos-ssh`](disa-stig-macos-ssh/README.md),
  con su servidor de laboratorio `macos-fips`.
- **RHEL 8 STIG** — ✅ **hecho**: perfil [`disa-stig-rhel-8-ssh`](disa-stig-rhel-8-ssh/README.md).
  Tras la lectura por regla resultó que las STIG son las 5.1.28/29/30 (allowlist FIPS 140-2),
  distintas de las reglas CIS Level 1/2 (el denylist) del mismo benchmark. Ningún fixture nuevo:
  el servidor `fips` del laboratorio ya lo pasa.
- **Ubuntu 20.04 LTS STIG** — ✅ **hecho**: perfil [`disa-stig-ubuntu-2004-ssh`](disa-stig-ubuntu-2004-ssh/README.md).
  Las «variantes» eran el *Audit/Remediation* (la lista mandada) frente al *Default Value* (ejemplo).
  El más estricto: solo AES-CTR. Sin fixture: `small-moduli` ya lo pasa.
- **Solaris 11 STIG** — ✅ **hecho**: perfil [`disa-stig-solaris-11-ssh`](disa-stig-solaris-11-ssh/README.md).
  La lectura por regla confirmó que el benchmark solo trae **una** regla de cripto SSH
  (`SOL-11.1-060130`, cifrados AES-CTR); no hay regla de MAC ni de KEX, así que el perfil es
  *allowlist solo de cifrado* — honesto, no inventado. X86 y SPARC imprimen la regla idéntica.
  Sin fixture: `small-moduli` ya lo pasa, `fips` lo falla.
- **VMware ESXi 8.0 STIG** — ✅ **hecho**: perfil [`disa-stig-esxi-ssh`](disa-stig-esxi-ssh/README.md).
  La lectura por regla confirmó una sola regla de cripto SSH (`ESXI-80-000187`, cifrados; audit con
  semántica de *allowlist* explícita «or a subset thereof»); sin regla de MAC ni KEX → solo cifrado.
  Sin fixture: `fips` ya lo pasa, `modern` lo falla.
- **VMware Photon OS 4.0 STIG** — ✅ **hecho**: perfil [`disa-stig-photon-ssh`](disa-stig-photon-ssh/README.md).
  Dos reglas *allowlist* (audit «or a subset thereof»): `PHTN-40-000079` (cifrados, los mismos cinco
  que ESXi) y `PHTN-40-000239` (MACs `hmac-sha2-512,hmac-sha2-256` planas, sin `-etm`); sin regla KEX.
  Primer STIG de VMware con MAC. Sin fixture: `small-moduli` ya lo pasa, `modern` lo falla.
- **Ubuntu 22.04 LTS STIG** — ✅ **hecho**: perfil [`disa-stig-ubuntu-2204-ssh`](disa-stig-ubuntu-2204-ssh/README.md).
  Más holgado que 20.04: cipher+GCM, MAC plano+etm, kex ECDH+`dhge-sha256`. Sin fixture:
  `small-moduli` pasa, `modern` falla.
- **Ubuntu 24.04 LTS STIG** — ✅ **hecho**: perfil [`disa-stig-ubuntu-2404-ssh`](disa-stig-ubuntu-2404-ssh/README.md).
  Cipher+MAC como RHEL 9, **pero** con regla KEX propia (grupos MODP 16/14). Sin fixture:
  `small-moduli` pasa, `modern` falla.

### Otros STIG de Linux — hallazgos del barrido del corpus

El barrido completo de los STIG cacheados reveló más plataformas. Dos categorías:

- **Ambiguos — dos juegos de reglas contradictorios (NO codificables literalmente).**
  El **Amazon Linux 2 STIG** y el **Debian 11 STIG** traen *dos* mandatos de cifrado/MAC/KEX
  que chocan: uno «fuerte» (con `chacha20-poly1305@openssh.com` y `curve25519`) y otro
  «FIPS 140-2» (solo AES-CTR / `hmac-sha2` plano). No hay *un* mandato único —depende del modo
  FIPS—, así que elegir uno sería suponer. Se quedan fuera hasta poder distinguir la condición.
- **Un perfil por documento, aunque la lista coincida hoy con otro (✅ hecho).** Decidido:
  identidad = documento (como RHEL 8 y 9 conviven). Tras leer cada uno por regla se añadieron:
  [`disa-stig-rhel-10-ssh`](disa-stig-rhel-10-ssh/README.md) y
  [`disa-stig-almalinux-9-ssh`](disa-stig-almalinux-9-ssh/README.md) y
  [`disa-stig-amazon-linux-2023-ssh`](disa-stig-amazon-linux-2023-ssh/README.md) (lista = RHEL 9);
  [`disa-stig-oracle-linux-8-ssh`](disa-stig-oracle-linux-8-ssh/README.md) (lista = RHEL 8, con
  `aes192-ctr` y KEX de 7 métodos);
  [`disa-stig-oracle-linux-7-ssh`](disa-stig-oracle-linux-7-ssh/README.md) y
  [`disa-stig-suse-15-ssh`](disa-stig-suse-15-ssh/README.md) (lista = Ubuntu 20.04). Cada uno cita
  su propio documento; si una plataforma revisa su lista, cambia solo su perfil. Sin fixtures nuevos.

### Equipos de red

- **HPE Aruba CX, F5 Networks** — la lista impresa es un **ejemplo de sintaxis** del comando (incluye
  `aes*-cbc`, `arcfour`, `hmac-sha1`), no la recomendación limpia. Hay que leer la regla real
  (probablemente un *denylist* «quita CBC/arcfour/SHA-1»). Docs en `docs/estandares/cis/equipos-de-red/`.
- **Juniper (Router NDM STIG)** — la regla `JUNI-ND-001200` pide «a FIPS 140-2 approved algorithm»
  (prosa) e imprime `ciphers aes128-cbc;` solo como **ejemplo de configuración** («as shown in the
  example below»). No es una lista mandada; codificar `aes128-cbc` (CBC, débil) sería un error. Sin
  fuente literal que codificar.

**Barrido del corpus completado.** Revisados todos los STIG cacheados con posible cripto SSH.
Los codificables (mandato único, lista literal) ya son perfil; el resto queda como:
*ambiguo* (Amazon Linux 2, Debian 11: reglas duales FIPS/no-FIPS) o *sin lista literal* (Juniper,
Aruba, F5: prosa o ejemplo de sintaxis). No hay más plataformas con allowlist SSH inequívoco.

### PCI DSS — ✅ perfil hecho y **verificado contra la fuente**

El perfil `pci-dss-4` está hecho y funciona (deriva de NIST/BSI/ISO, que es a lo que la propia norma
remite). El documento primario —antes ausente por no ser redistribuible— ya está **archivado** en
la copia de referencia interna (`estandares/pci-ssc/PCI-DSS-v4_0_1.pdf`). Con él se
**verificó** el perfil: requisitos 2.2.7 y 4.2.1 existen tal cual, y la definición de *Strong
Cryptography* del **Apéndice G** («minimum of 112-bits of effective key strength») coincide con el
`minimum_security_strength: 112` codificado, incluida la recomendación de 128 bits y las cuatro
referencias (NIST SP 800-57 Pt.1, BSI TR-02102-1, ECRYPT-CSA D5.4, ISO/IEC 18033).
