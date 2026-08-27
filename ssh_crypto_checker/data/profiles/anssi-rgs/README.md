# `data/profiles/anssi-rgs/` — ANSSI (regles cryptographiques)

**ANSSI (France)**. La base francesa. ANSSI publica reglas por mecanismo y parámetro, no listas de algoritmos SSH, así que este perfil codifica las reglas en vez de inventarse una configuración.

Combina tres documentos: PG-083 para las reglas, PA-079 para el estado de cada algoritmo y DAT-NT-007 para lo específico de SSH.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `pg-083-v3-00.json` | `anssi-rgs@pg-083-v3-00` | ANSSI-PG-083 v3.00 (2026-03-20), with ANSSI-PA-079 v1.0 and DAT-NT-007 v1.3 | sí |

Añadir una edición es añadir un fichero aquí; con más de una,
exactamente una debe llevar `"current": true`.

> **Fuente**: ANSSI-PG-083 'Regles et recommandations concernant le choix et le dimensionnement des mecanismes cryptographiques' v3.00; algorithm status from ANSSI-PA-079 'Guide de selection d'algorithmes cryptographiques' v1.0; SSH specifics from DAT-NT-007 'Recommandations pour un usage securise d'(Open)SSH' v1.3.
>
> https://cyber.gouv.fr/publications/mecanismes-cryptographiques
