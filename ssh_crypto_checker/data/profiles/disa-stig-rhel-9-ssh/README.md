# `data/profiles/disa-stig-rhel-9-ssh/` — DISA STIG, SSH server (RHEL 9)

**DISA (Departamento de Defensa de EE. UU.)**. El endurecimiento SSH del DoD tal
y como lo detalla la **RHEL 9 STIG**: un ***allowlist* FIPS 140-3**. Al revés que
el CIS Benchmark —que quita algoritmos débiles y permite el resto—, la STIG
nombra los **únicos** cifrados y MAC admitidos y rechaza todo lo demás (incluido
ChaCha20-Poly1305, que CIS sí acepta).

Solo restringe **cifrado** y **MAC**: la RHEL 9 STIG no fija en su regla de SSH
el intercambio de claves ni la clave de host (los gobierna la política
criptográfica FIPS del sistema), así que el perfil no declara regla para esas
clases.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `rhel-9-v1.0.0.json` | `disa-stig-rhel-9-ssh@rhel-9-v1.0.0` | Red Hat Enterprise Linux 9 STIG Benchmark v1.0.0 | sí |

> **Ojo con el alcance:** la criptografía SSH de las STIG **no es uniforme entre
> plataformas**. La RHEL 8 STIG admite además `chacha20-poly1305@openssh.com` y
> `aes192-ctr`; la Ubuntu 20.04 STIG usa otra combinación. Por eso este perfil se
> ancla a la **RHEL 9 STIG** y lo dice: otras plataformas serían perfiles
> distintos, no ediciones de este (codifican reglas distintas, no una revisión
> posterior de la misma regla).

Añadir una edición es añadir un fichero aquí; con más de una, exactamente una
debe llevar `"current": true`.

> **Fuente**: CIS Red Hat Enterprise Linux 9 STIG Benchmark v1.0.0, reglas
> «RHEL 9 must implement DOD-approved encryption ciphers» y «… MACs employing
> FIPS 140-3 validated cryptographic hash algorithms». Los documentos STIG están
> en `docs/estandares/disa-stig/`.
>
> https://www.cisecurity.org/cis-benchmarks
