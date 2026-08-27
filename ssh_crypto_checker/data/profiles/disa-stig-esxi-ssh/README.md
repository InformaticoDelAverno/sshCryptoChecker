# `data/profiles/disa-stig-esxi-ssh/` — DISA STIG, SSH server (VMware ESXi 8.0)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para el hipervisor **VMware ESXi 8.0**: un ***allowlist* de cifrado FIPS 140-2**
(dos AES-GCM y tres AES-CTR). El STIG de ESXi solo enuncia **una** regla de
cripto SSH —la de cifrados—, así que este perfil restringe **cifrados y nada
más**.

> **Solo cifrado, a propósito.** El benchmark no trae regla de MACs ni de
> intercambio de claves para SSH. Codificar una que el documento no manda sería
> inventar; las clases sin regla no se comprueban.

> **`esxcli`, no `sshd_config`.** ESXi fija sus cifrados con
> `esxcli system ssh server config`, no con una línea `Ciphers`. Pero eso es
> solo *cómo* se pone la lista; lo que esta herramienta mide es lo que el
> servidor **ofrece por el cable**, que es justo lo que el *allowlist* gobierna.
> El audit lo dice literal: los cifrados ofrecidos siendo la lista esperada «or
> a subset thereof» **no** es hallazgo; cualquiera fuera de ella, **sí**.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `esxi-8.0-v1.0.0.json` | `disa-stig-esxi-ssh@esxi-8.0-v1.0.0` | VMware vSphere 8.0 ESXi STIG Benchmark v1.0.0 | sí |

> **Alcance:** la criptografía SSH de las STIG **varía por plataforma**. El
> **vSphere 7.0 ESXi STIG** (misma lista de cifrados) y los STIG de **Photon OS**
> (el SO de las *appliances* de vCenter) son documentos distintos, no ediciones
> de este. Ver también [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md),
> [`disa-stig-solaris-11-ssh`](../disa-stig-solaris-11-ssh/README.md) (también
> solo cifrado, pero sin GCM) y el resto de STIG.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS VMware vSphere 8.0 ESXi STIG Benchmark v1.0.0, regla
> `ESXI-80-000187` (V-258750) «The ESXi host Secure Shell (SSH) daemon must be
> configured to only use FIPS 140-2 validated ciphers». El documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
