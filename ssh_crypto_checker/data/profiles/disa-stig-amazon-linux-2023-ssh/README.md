# `data/profiles/disa-stig-amazon-linux-2023-ssh/` — DISA STIG, SSH server (Amazon Linux 2023)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Amazon Linux 2023**: un ***allowlist* FIPS** de cifrados y MACs, fijado a
través de las *crypto-policies* del sistema. Sus listas **coinciden** con las del
STIG de RHEL 9 (linaje común de *crypto-policy*), pero este es el **documento de
Amazon Linux 2023**, citado y versionado por su cuenta.

> **`opensshserver.config`, no `sshd_config`.** Amazon Linux 2023 fija la cripto
> por `/etc/crypto-policies/back-ends/opensshserver.config`; pero eso es solo
> *cómo* se pone la lista. Lo que medimos es lo que el servidor **ofrece por el
> cable**, que es lo que el *allowlist* gobierna.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `amazon-linux-2023-v1.0.0.json` | `disa-stig-amazon-linux-2023-ssh@amazon-linux-2023-v1.0.0` | Amazon Linux 2023 STIG Benchmark v1.0.0 | sí |

No fija regla de KEX: restringe cifrados y MACs. Ver
[`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md).

> **Fuente**: CIS Amazon Linux 2023 STIG Benchmark v1.0.0, reglas SSH de cifrados
> y MACs FIPS 140-2/140-3. En
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
