# `data/profiles/disa-stig-oracle-linux-8-ssh/` — DISA STIG, SSH server (Oracle Linux 8)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Oracle Linux 8**: un ***allowlist* FIPS 140-2** de cifrados, MACs **e
intercambio de claves**, fijado por las *crypto-policies* del sistema. Al ser
compatible con RHEL 8, sus listas **coinciden** con las del STIG de RHEL 8
—mantiene `aes192-ctr` y un KEX de siete métodos—, pero este es el **documento de
Oracle Linux 8**, citado y versionado por su cuenta.

> **`opensshserver.config`, no `sshd_config`.** Fija la cripto por
> `/etc/crypto-policies/back-ends/opensshserver.config`; medimos lo ofrecido por
> el cable, que es lo que el *allowlist* gobierna.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `oracle-linux-8-v1.0.0.json` | `disa-stig-oracle-linux-8-ssh@oracle-linux-8-v1.0.0` | Oracle Linux 8 STIG Benchmark v1.0.0 | sí |

A diferencia de RHEL 9, RHEL 8 (y por tanto Oracle Linux 8) **sí** fija KEX. Ver
[`disa-stig-rhel-8-ssh`](../disa-stig-rhel-8-ssh/README.md).

> **Fuente**: CIS Oracle Linux 8 STIG Benchmark v1.0.0, reglas SSH de cifrados,
> MACs e intercambio de claves FIPS-validados. En
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
