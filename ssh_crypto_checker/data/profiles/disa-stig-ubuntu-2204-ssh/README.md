# `data/profiles/disa-stig-ubuntu-2204-ssh/` — DISA STIG, SSH server (Ubuntu 22.04)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD
para **Ubuntu 22.04 LTS**: un ***allowlist* FIPS 140-3**, más **holgado** que el
de Ubuntu 20.04 — mantiene AES-GCM junto a AES-CTR y acepta las variantes
*encrypt-then-MAC* además de las planas.

> **Ojo — no confundir con Ubuntu 20.04.** El STIG de 20.04 era el más estricto
> (solo AES-CTR, MAC plano). El de 22.04 afloja cifrado y MAC; el intercambio de
> claves es el mismo (ECDH + `dhge-sha256`, sin curve25519). Ver
> [`disa-stig-ubuntu-2004-ssh`](../disa-stig-ubuntu-2004-ssh/README.md) y
> [`disa-stig-ubuntu-2404-ssh`](../disa-stig-ubuntu-2404-ssh/README.md).

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `ubuntu-2204-v1.0.0.json` | `disa-stig-ubuntu-2204-ssh@ubuntu-2204-v1.0.0` | Ubuntu 22.04 LTS STIG Benchmark v1.0.0 | sí |

> **«Orden exacto».** El STIG pide las listas «in exact order»; esta herramienta
> comprueba el equivalente observable por el cable —que el servidor **solo**
> ofrezca algoritmos de la lista—, porque el orden es un detalle del fichero de
> configuración, no una propiedad del protocolo.

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Ubuntu 22.04 LTS STIG Benchmark v1.0.0, reglas `SV-260531`
> (cifrados), `SV-260532` (MACs) y `SV-260533` (intercambio de claves). El
> documento está en
> `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
