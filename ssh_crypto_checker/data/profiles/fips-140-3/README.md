# `data/profiles/fips-140-3/` — FIPS 140-3 approved algorithms

**NIST**. Solo funciones aprobadas por FIPS. Deja fuera ChaCha20-Poly1305 y UMAC, que no tienen aprobación de NIST por buenos que sean.

Que un algoritmo no esté aquí no significa que sea débil: significa que nadie lo ha certificado.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `annex-c.json` | `fips-140-3@annex-c` | FIPS 140-3 approved functions (Annex C / SP 800-140C), with FIPS 186-5 and SP 800-56A Rev. 3 | sí |

Añadir una edición es añadir un fichero aquí; con más de una,
exactamente una debe llevar `"current": true`.

> **Fuente**: FIPS 140-3 (funciones aprobadas en el Annex C / SP 800-140C), FIPS 186-5, SP 800-56A Rev. 3, SP 800-38D
>
> https://csrc.nist.gov/projects/cryptographic-module-validation-program
