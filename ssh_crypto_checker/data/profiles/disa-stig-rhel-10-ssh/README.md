# `data/profiles/disa-stig-rhel-10-ssh/` — DISA STIG, SSH server (RHEL 10)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Red Hat Enterprise Linux 10**: un ***allowlist* FIPS 140-3** de cifrados
y MACs. Sus listas **coinciden hoy** con las del STIG de RHEL 9, pero este es el
**documento de RHEL 10**, citado y versionado por su cuenta.

> **Un perfil por documento.** El directorio identifica la norma. RHEL 10 STIG
> es un documento distinto del de RHEL 9, con su propio calendario; si mañana
> revisa su lista, cambia este perfil y no el de RHEL 9. Por eso son separados
> —igual que [`disa-stig-rhel-8-ssh`](../disa-stig-rhel-8-ssh/README.md) y
> [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md) conviven.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `rhel-10-v1.0.0.json` | `disa-stig-rhel-10-ssh@rhel-10-v1.0.0` | Red Hat Enterprise Linux 10 STIG Benchmark v1.0.0 | sí |

Como RHEL 9, no fija reglas de intercambio de claves ni de clave de host (los
rige la *crypto-policy* del sistema), así que el perfil restringe cifrados y MACs.

> **Fuente**: CIS Red Hat Enterprise Linux 10 STIG Benchmark v1.0.0, reglas SSH
> de cifrados y MACs aprobados por el DoD. En
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
