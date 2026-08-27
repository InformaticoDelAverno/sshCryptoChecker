# `data/profiles/disa-stig-photon-ssh/` — DISA STIG, SSH server (VMware Photon OS 4.0)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **VMware Photon OS 4.0** —el Linux que corre la *appliance* de vCenter
Server—. Dos ***allowlists* FIPS**: cifrados (dos AES-GCM y tres AES-CTR) y MACs
(HMAC-SHA-2 en forma plana). El STIG de Photon no enuncia regla de intercambio
de claves, así que este perfil restringe **cifrados y MACs, y nada más**.

> **El primer STIG de VMware aquí con regla de MAC.** A diferencia del de ESXi
> —cuya única regla SSH es la de cifrados, puesta por `esxcli`—, Photon es un
> OpenSSH normal sobre `sshd_config` y **añade** la regla de MACs. Ambas reglas
> son *allowlists*: el audit dice literal que la lista ofrecida siendo la
> esperada «or a subset thereof» **no** es hallazgo, y cualquiera fuera **sí**.

> **MACs planas, no `-etm`.** La regla nombra `hmac-sha2-512` y `hmac-sha2-256`
> en su forma plana; un servidor que ofrezca `hmac-sha2-256-etm@openssh.com`
> **falla** (donde el RHEL 9 STIG no lo haría).

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `photon-4.0-v1.0.0.json` | `disa-stig-photon-ssh@photon-4.0-v1.0.0` | VMware vSphere 8.0 vCenter Appliance Photon OS 4.0 STIG Benchmark v1.0.0 | sí |

> **Alcance:** la criptografía SSH de las STIG **varía por plataforma**. El STIG
> de **ESXi** ([`disa-stig-esxi-ssh`](../disa-stig-esxi-ssh/README.md), mismos
> cifrados pero sin regla de MAC) y los demás STIG de *appliance* de vSphere son
> documentos distintos, no ediciones de este. Ver también el resto de STIG.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS VMware vSphere 8.0 vCenter Appliance Photon OS 4.0 STIG
> Benchmark v1.0.0, reglas `PHTN-40-000079` (V-258835, cifrados) y
> `PHTN-40-000239` (V-258900, MACs). El documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
