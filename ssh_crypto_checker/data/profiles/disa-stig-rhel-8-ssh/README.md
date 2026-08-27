# `data/profiles/disa-stig-rhel-8-ssh/` — DISA STIG, SSH server (RHEL 8)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **RHEL 8**, tomado de las reglas del benchmark marcadas «Profile
Applicability: STIG» (5.1.28/29/30): un ***allowlist* FIPS 140-2** de cifrados,
MAC e intercambio de claves. Más amplio que el de RHEL 9 (mantiene los cifrados
AES-CTR y fija una lista de intercambio de claves), pero sigue siendo
*allowlist*: lo que no nombra, falla.

> **Ojo — el mismo benchmark trae dos tipos de regla.** Las de **Level 1/2** son
> el *denylist* CIS de siempre (ya codificado por
> [`cis-benchmark-ssh`](../cis-benchmark-ssh/README.md)); las **STIG**
> (5.1.28/29/30) son *allowlists* FIPS. Este perfil codifica solo las STIG.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `rhel-8-v2.0.0.json` | `disa-stig-rhel-8-ssh@rhel-8-v2.0.0` | Red Hat Enterprise Linux 8 STIG Benchmark v2.0.0 | sí |

> **Alcance:** la criptografía SSH de las STIG **varía por plataforma**. Ver
> también [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md) (más
> estrecho, sin regla de intercambio de claves) y
> [`disa-stig-macos-ssh`](../disa-stig-macos-ssh/README.md) (P-256, un solo
> cifrado). Cada uno codifica un STIG distinto, no una edición del otro.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Red Hat Enterprise Linux 8 STIG Benchmark v2.0.0, reglas
> 5.1.28 (MACs), 5.1.29 (ciphers) y 5.1.30 (key exchange), todas «employing FIPS
> 140-2-approved algorithms». El documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
