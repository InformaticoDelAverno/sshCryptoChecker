# sshCryptoChecker

Audit the cryptography your SSH servers are willing to negotiate — key
exchange, host keys, ciphers, MACs, compression — grade each server, check it
against published standards (NIST, FIPS, CNSA, BSI, ENS, PCI DSS, CIS, ANSSI,
ISO, DISA STIG), and get the `sshd_config` block that fixes what it finds.
Zero dependencies; the tool speaks English and Spanish (`--lang en|es`).

**→ [English manual](docs/en/README.md)**

---

Auditoría de la criptografía que negocian tus servidores SSH — intercambio de
claves, claves de host, cifrado, MAC y compresión — con nota por servidor,
conformidad con normativas publicadas (NIST, FIPS, CNSA, BSI, ENS, PCI DSS,
CIS, ANSSI, ISO, DISA STIG) y el bloque de `sshd_config` que corrige lo que
encuentre. Sin dependencias; la herramienta habla inglés y español
(`--lang en|es`).

**→ [Manual en español](docs/es/README.md)**

---

## Mapa del repositorio

| Ruta | Qué contiene |
|---|---|
| [`docs/`](docs/README.md) | Los dos manuales ([español](docs/es/README.md) e [inglés](docs/en/README.md)) y las guías de extensión, bilingües. |
| `ssh_crypto_checker/` | Todo el código de la herramienta. |
| `tests/` | La suite y los trinquetes de cobertura. **Interno.** |
| `lab/` | El laboratorio Docker de servidores SSH contra los que corre la suite end to end. **Interno.** |
| `tools/` | Las puertas de desarrollo: cobertura del laboratorio, mutación, *lint* y el motor de release. **Interno.** |
| `examples/` | Un inventario de ejemplo para copiar y editar. |
| `ssh-crypto-checker` | Un lanzador para usar la herramienta **sin instalarla**. |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | La imagen, el arranque y el contexto de construcción de la **interfaz web**. |
| `Makefile` | Atajos de empaquetado, pruebas y las dos webs (producto y laboratorio). |
| `pyproject.toml` | Metadatos del paquete y la configuración de ruff y mypy. |
| `.coveragerc` | La configuración de cobertura, con `fail_under = 100` y **sin exclusiones**. |
| `.gitlab-ci.yml` | La CI: pruebas, lint, empaquetado y las puertas del laboratorio. |
| `.gitignore`, `LICENSE`, `CHANGELOG.md` | Exclusiones de git, licencia (MIT) y registro de cambios. |

---

License / Licencia: [MIT](LICENSE) · [Changelog](CHANGELOG.md)
