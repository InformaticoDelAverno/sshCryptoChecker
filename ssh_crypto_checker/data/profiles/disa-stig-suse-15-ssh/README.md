# `data/profiles/disa-stig-suse-15-ssh/` — DISA STIG, SSH server (SUSE Linux Enterprise 15)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **SUSE Linux Enterprise Server 15**: un ***allowlist* FIPS** estricto —solo
cifrados AES-CTR, MACs HMAC-SHA-2 planos y un intercambio de claves ECDH/DH-
group-exchange—. Sus listas **coinciden** con las de los STIG de Ubuntu 20.04 y
Oracle Linux 7, pero este es el **documento de SLES 15**, citado y versionado
por su cuenta.

> **Un perfil por documento.** SLES 15 STIG es un documento distinto con su
> calendario, aunque su lista coincida hoy con otras. Ver
> [`disa-stig-ubuntu-2004-ssh`](../disa-stig-ubuntu-2004-ssh/README.md) y
> [`disa-stig-oracle-linux-7-ssh`](../disa-stig-oracle-linux-7-ssh/README.md).

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `suse-15-v1.0.0.json` | `disa-stig-suse-15-ssh@suse-15-v1.0.0` | SUSE Linux Enterprise Server 15 STIG Benchmark v1.0.0 | sí |

> **«Orden exacto».** El STIG pide las listas «in exact order»; comprobamos el
> equivalente observable por el cable —que el servidor **solo** ofrezca
> algoritmos de la lista—.

> **Fuente**: CIS SUSE Linux Enterprise Server 15 STIG Benchmark v1.0.0, reglas
> SSH de cifrados, MACs e intercambio de claves. En
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
