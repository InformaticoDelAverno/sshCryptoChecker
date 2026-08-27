# `data/profiles/disa-stig-solaris-11-ssh/` — DISA STIG, SSH server (Solaris 11)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Oracle Solaris 11**. A diferencia de los STIG de RHEL y Ubuntu, el de
Solaris 11 solo enuncia **una** regla de cripto SSH: un ***allowlist* de
cifrado, solo AES-CTR** (`aes256-ctr, aes192-ctr, aes128-ctr`). Por eso este
perfil restringe **cifrados y nada más**.

> **Solo cifrado, a propósito.** El benchmark no trae regla de MACs ni de
> intercambio de claves para SSH (la única mención de «mac» es `mac-nospoof`,
> protección de enlace de datos, ajena a SSH). Codificar un MAC o un KEX que el
> documento no manda sería inventar; las clases sin regla no se comprueban.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `solaris-11-v1.0.0.json` | `disa-stig-solaris-11-ssh@solaris-11-v1.0.0` | Oracle Solaris 11 STIG Benchmark v1.0.0 | sí |

> **X86 y SPARC.** Las ediciones X86 y SPARC del benchmark imprimen la regla
> `SOL-11.1-060130` / `V-216173` de forma idéntica, así que una sola edición
> cubre ambas arquitecturas.

> **Alcance:** la criptografía SSH de las STIG **varía por plataforma**. Ver
> también [`disa-stig-rhel-9-ssh`](../disa-stig-rhel-9-ssh/README.md),
> [`disa-stig-rhel-8-ssh`](../disa-stig-rhel-8-ssh/README.md),
> [`disa-stig-ubuntu-2004-ssh`](../disa-stig-ubuntu-2004-ssh/README.md) (mismo
> cifrado CTR pero con reglas propias de MAC y KEX) y
> [`disa-stig-macos-ssh`](../disa-stig-macos-ssh/README.md). Cada uno codifica un
> STIG distinto, no una edición del otro.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Oracle Solaris 11 STIG Benchmark v1.0.0, regla
> `SOL-11.1-060130` (V-216173) «The operating system must implement DoD-approved
> encryption to protect the confidentiality of remote access sessions». El
> documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
