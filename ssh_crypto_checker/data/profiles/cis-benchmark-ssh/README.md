# `data/profiles/cis-benchmark-ssh/` — CIS Benchmark, SSH server

**Center for Internet Security**. El endurecimiento que más se exige en auditorías comerciales. Funciona **por exclusión**: quita algoritmos nombrados y permite lo que no nombra.

La edición cita seis benchmarks (Ubuntu 22.04 y 24.04, Debian 11 y 12, RHEL 8 y 9) porque los seis comparten el mismo cuerpo de reglas. Las listas siguen las expresiones de auditoría que los benchmarks comprueban de verdad, que para los cifrados son más amplias que la cadena de remediación.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `2025-10.json` | `cis-benchmark-ssh@2025-10` | Ubuntu 22.04 v3.0.0 (2025-10-30), Ubuntu 24.04 v1.0.0, Debian 11 v2.0.0, Debian 12 v1.1.0, RHEL 8 v4.0.0, RHEL 9 v2.0.0 | sí |

Añadir una edición es añadir un fichero aquí; con más de una,
exactamente una debe llevar `"current": true`.

> **Fuente**: CIS Linux Benchmarks, rules 'Ensure sshd Ciphers / KexAlgorithms / MACs are configured'. The lists below follow the audit regular expressions the benchmarks actually test with, which for Ciphers are broader than the remediation string.
>
> https://www.cisecurity.org/cis-benchmarks
