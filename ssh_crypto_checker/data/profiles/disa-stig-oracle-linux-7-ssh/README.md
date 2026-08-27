# `data/profiles/disa-stig-oracle-linux-7-ssh/` — DISA STIG, SSH server (Oracle Linux 7)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Oracle Linux 7**: un ***allowlist* FIPS** estricto —solo cifrados
AES-CTR, MACs HMAC-SHA-2 planos y un intercambio de claves ECDH/DH-group-
exchange—. Sus listas **coinciden** con las del STIG de Ubuntu 20.04, pero este
es el **documento de Oracle Linux 7**, citado y versionado por su cuenta.

> **Un perfil por documento.** Aunque la lista coincida hoy con la de Ubuntu
> 20.04, Oracle Linux 7 STIG es un documento distinto con su calendario. Ver
> [`disa-stig-ubuntu-2004-ssh`](../disa-stig-ubuntu-2004-ssh/README.md).

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `oracle-linux-7-v1.0.0.json` | `disa-stig-oracle-linux-7-ssh@oracle-linux-7-v1.0.0` | Oracle Linux 7 STIG Benchmark v1.0.0 | sí |

> **«Orden exacto».** El STIG pide las listas «in exact order»; comprobamos el
> equivalente observable por el cable —que el servidor **solo** ofrezca
> algoritmos de la lista—.

> **Fuente**: CIS Oracle Linux 7 STIG Benchmark v1.0.0, regla `OL07-00-021350`
> (intercambio de claves) y las de cifrados y MACs. En
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
