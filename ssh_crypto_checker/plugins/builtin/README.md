# `ssh_crypto_checker/plugins/builtin/` — las comprobaciones de serie

Quince, cada una en su fichero. Borrar cualquiera de ellos cambia lo que el
informe dice y **no** cambia la nota: eso lo decide `assessment.py`. Son la
demostración de que la interfaz de plugins es la misma que usa la herramienta
consigo misma, y no un añadido para terceros.

Hay tres tipos: `check` mira un servidor, `fleet` mira todos a la vez, y
`vulnerability` añade detecciones a las que ya trae la política.

## Ficheros

| Fichero | Tipo | Qué mira |
|---|---|---|
| `__init__.py` | — | Marca el directorio como paquete; el cargador lo recorre entero. |
| `algorithm_classes.py` | check | Qué opina la política de cada algoritmo que el servidor ofrece: cifrados, MAC, intercambio de claves y compresión. |
| `protocol_features.py` | check | Las propiedades de la negociación en sí: intercambio estricto (`strict-kex`), `ext-info`, algoritmo preferido. |
| `host_key_sizes.py` | check | El tamaño de las claves de host y el del grupo Diffie-Hellman por el que se obtuvieron. |
| `host_certificates.py` | check | Validez de los certificados de host: caducados, aún no válidos, sin CA. |
| `certificate_lifetime.py` | vulnerability | Certificados de host válidos durante demasiado tiempo. |
| `rsa_key_quality.py` | vulnerability | Claves RSA cuya aritmética está mal: exponente 3, módulo con factores pequeños, módulo negativo. |
| `auth_methods.py` | check | Qué acepta el servidor como prueba de identidad — incluido el caso peor: que no exija ninguna. |
| `preauth_capacity.py` | check | Cuán barato es agotar los huecos de preautenticación (`MaxStartups`). |
| `sshfp_records.py` | check | Las claves observadas contra los registros SSHFP publicados para ese nombre. |
| `known_hosts_record.py` | check | La clave del servidor contra la que un cliente ya tiene apuntada: revocada, cambiada o ausente. |
| `shared_host_keys.py` | fleet | Claves de host presentadas por más de un servidor del escaneo. Solo se ve mirando la flota entera. |
| `client_audit.py` | check | El cliente ssh de **esta** máquina: qué negociaría él. |
| `server_directives.py` | check | Las directivas que `sshd` resolvió de verdad, y los bloques `Match` que las sobrescriben. |
| `server_files.py` | check | Los ficheros de los que `sshd` depende: permisos, `moduli` y el paquete instalado. |
| `server_accounts.py` | check | Quién puede entrar y qué se dejó por ahí: `authorized_keys`, claves privadas sin contraseña. |
