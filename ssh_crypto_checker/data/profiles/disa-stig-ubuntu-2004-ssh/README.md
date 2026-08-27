# `data/profiles/disa-stig-ubuntu-2004-ssh/` — DISA STIG, SSH server (Ubuntu 20.04)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Ubuntu 20.04 LTS**, de las reglas del benchmark marcadas «Profile
Applicability: STIG»: un ***allowlist* FIPS 140-2**, y el **más estricto** de
los STIG de Linux en cifrado — **solo AES-CTR**, sin GCM ni ChaCha20 —, con
intercambio de claves ECDH/DH-group-exchange y HMAC-SHA-2 en su forma plana.

> **Ojo — dos tipos de regla en el mismo benchmark.** Las de **Level 1/2** son
> el *denylist* CIS (ya en [`cis-benchmark-ssh`](../cis-benchmark-ssh/README.md));
> las **STIG** son *allowlists* FIPS. Este perfil codifica solo las STIG, y toma
> la lista de su *Audit/Remediation*, no del *Default Value* (que es el OpenSSH
> por defecto que la regla reemplaza).

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `ubuntu-2004-v2.0.0.json` | `disa-stig-ubuntu-2004-ssh@ubuntu-2004-v2.0.0` | Ubuntu 20.04 LTS STIG Benchmark v2.0.0 | sí |

> **Alcance:** la criptografía SSH de las STIG **varía por plataforma**. Ver
> también [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md),
> [`disa-stig-rhel-8-ssh`](../disa-stig-rhel-8-ssh/README.md) (mantiene GCM y
> fija otro intercambio de claves) y
> [`disa-stig-macos-ssh`](../disa-stig-macos-ssh/README.md). Cada uno codifica un
> STIG distinto, no una edición del otro.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Ubuntu 20.04 LTS STIG Benchmark v2.0.0, reglas «STIG» de
> cifrados, MACs (4.2.27) e intercambio de claves «FIPS-approved/validated». El
> documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
