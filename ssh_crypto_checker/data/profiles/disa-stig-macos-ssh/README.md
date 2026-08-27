# `data/profiles/disa-stig-macos-ssh/` — DISA STIG, SSH server (macOS 15)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **macOS 15 (Sequoia)**: un ***allowlist* FIPS** muy estrecho, construido
alrededor de la curva **P-256**. Solo conforman `aes128-gcm@openssh.com`,
`ecdh-sha2-nistp256`, HMAC-SHA-256 (en sus formas EtM y plana) y las claves de
host ECDSA sobre P-256; cualquier otra cosa —aunque sea fuerte, como AES-256,
curve25519 o Ed25519— **falla**.

A diferencia del `disa-stig-rhel-9-ssh` (RHEL 9), este perfil **sí** fija la clave de
host y el intercambio de claves, porque la regla de macOS los nombra.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `macos-15-v1.0.0.json` | `disa-stig-macos-ssh@macos-15-v1.0.0` | Apple macOS 15 (Sequoia) STIG Benchmark v1.0.0 | sí |

> **Alcance:** la criptografía SSH de las STIG **varía por plataforma**; este
> perfil es la **macOS 15 STIG** en concreto (la RHEL 9 está en
> [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md), y fija otro conjunto). Otras
> plataformas serían perfiles distintos, no ediciones de este.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Apple macOS 15 (Sequoia) STIG Benchmark v1.0.0, regla «SSHD
> must be configured to limit … to FIPS-compliant connections» (array
> `fips_sshd_config`). El documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
