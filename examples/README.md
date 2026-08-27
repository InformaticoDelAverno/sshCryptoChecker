# `examples/` — ejemplos

## Ficheros

| Fichero | Qué es |
|---|---|
| `servers.txt` | Un inventario de ejemplo, con las cuatro formas de nombrar un objetivo (host, `host:puerto`, IP, `[IPv6]:puerto`), etiquetas, comentarios y opciones por servidor. Sirve para copiarlo y editarlo: `ssh-crypto-checker -f examples/servers.txt`. |

Las contraseñas literales **no se aceptan** en un inventario: solo
`password-file=` o `password-env=`. Un fichero de inventario acaba en un
repositorio, y una contraseña dentro de él acaba en el historial.
