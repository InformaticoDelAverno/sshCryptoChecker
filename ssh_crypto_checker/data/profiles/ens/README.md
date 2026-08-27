# `data/profiles/ens/` — ENS (Esquema Nacional de Seguridad)

**CCN (Spain)**. La base del sector público español. CCN-STIC-807 clasifica cada algoritmo como Recomendado o Legacy.

La ventana de Legacy cerró el 31 de diciembre de 2025, así que solo queda la columna de Recomendado. Base legal: Real Decreto 311/2022.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `2022-05.json` | `ens@2022-05` | CCN-STIC-807 Mayo 2022, tables 4-4 to 4-7; Real Decreto 311/2022 | sí |

Añadir una edición es añadir un fichero aquí; con más de una,
exactamente una debe llevar `"current": true`.

> **Fuente**: CCN-STIC-807 'Criptologia de empleo en el ENS' (Mayo 2022) section 4.2, which states 'La unica version de SSH autorizada es SSHv2' and gives per-algorithm tables. Legal basis: Real Decreto 311/2022 measures op.exp.10 (Proteccion de claves criptograficas, refuerzo R1 'Se emplearan algoritmos y parametros autorizados por el CCN'), mp.com.2 and mp.com.3.
>
> https://www.ccn-cert.cni.es/es/series-ccn-stic/800-guia-esquema-nacional-de-seguridad/513-ccn-stic-807-criptologia-de-empleo-en-el-ens/file
