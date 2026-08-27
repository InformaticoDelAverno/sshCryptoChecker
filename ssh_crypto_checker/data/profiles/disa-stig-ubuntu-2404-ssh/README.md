# `data/profiles/disa-stig-ubuntu-2404-ssh/` — DISA STIG, SSH server (Ubuntu 24.04)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Ubuntu 24.04 LTS**: un ***allowlist* FIPS 140-3**. Los **mismos** cuatro
cifrados y cuatro MACs que el STIG de RHEL 9, pero —a diferencia de RHEL 9— este
**sí** fija una lista de intercambio de claves.

> **Distinto de RHEL 9 y de Ubuntu 22.04.** Cipher y MAC coinciden con RHEL 9,
> pero RHEL 9 deja el KEX a la *crypto-policy* del sistema y no lo fija; aquí sí
> (ECDH + `dhge-sha256` + grupos MODP SHA-2 16 y 14, sin curve25519). Y frente a
> [`disa-stig-ubuntu-2204-ssh`](../disa-stig-ubuntu-2204-ssh/README.md), este
> quita `aes192-ctr` y usa otro MAC/KEX.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `ubuntu-2404-v1.0.0.json` | `disa-stig-ubuntu-2404-ssh@ubuntu-2404-v1.0.0` | Ubuntu 24.04 LTS STIG Benchmark v1.0.0 | sí |

> **sshd + cliente, misma lista.** El benchmark fija cada lista para
> `/etc/ssh/sshd_config` y `/etc/ssh/ssh_config` con idéntico contenido: un solo
> mandato por clase. Y pide «orden exacto»; comprobamos el equivalente observable
> por el cable (que el servidor **solo** ofrezca algoritmos de la lista).

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Ubuntu 24.04 LTS STIG Benchmark v1.0.0, reglas `SV-270667`
> (cifrados), `SV-270668` (MACs) y `SV-270669` (intercambio de claves). El
> documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
