# `data/profiles/disa-stig-almalinux-9-ssh/` — DISA STIG, SSH server (AlmaLinux OS 9)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **AlmaLinux OS 9**: un ***allowlist* FIPS** de cifrados y MACs. Al ser un
*rebuild* compatible con RHEL 9, sus listas **coinciden** con las del STIG de
RHEL 9, pero este es el **documento de AlmaLinux**, citado y versionado por su
cuenta.

> **Un perfil por documento.** AlmaLinux 9 STIG es un documento distinto con su
> propio calendario, aunque su lista coincida hoy con la de RHEL 9. Ver
> [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md).

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `almalinux-9-v1.0.0.json` | `disa-stig-almalinux-9-ssh@almalinux-9-v1.0.0` | Cloud Linux AlmaLinux OS 9 STIG Benchmark v1.0.0 | sí |

Como RHEL 9, no fija reglas de KEX ni de clave de host: restringe cifrados y MACs.

> **Fuente**: CIS Cloud Linux AlmaLinux OS 9 STIG Benchmark v1.0.0, reglas SSH
> de cifrados y MACs (comprobadas contra el fichero `openssh.config`). En
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
