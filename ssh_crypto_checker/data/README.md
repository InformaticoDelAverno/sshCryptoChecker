# `ssh_crypto_checker/data/` — lo editable

Datos, no código. Todo lo que se puede cambiar sin tocar Python está aquí, y
`--export-policy` saca una copia para editarla.

Se instala con el paquete: `pyproject.toml` declara `data/*.json`,
`data/profiles/*/*.json` **y** `data/i18n/*.json`, porque el primer patrón no
alcanza subdirectorios y un *wheel* se habría quedado sin normativas ni
traducciones — en silencio, porque una normativa que falta se parece a una
normativa que nadie definió.

## Ficheros

| Fichero | Qué contiene |
|---|---|
| `algorithms.json` | La política: los algoritmos con su categoría y su motivo, las 65 vulnerabilidades conocidas con su detección, las bandas de fuerza de seguridad, los pesos y la escala de notas, los topes de nota y las comprobaciones de configuración. Es el fichero que se edita para cambiar el criterio sin cambiar la herramienta. |

## Subdirectorios

| Directorio | Qué contiene |
|---|---|
| [`profiles/`](profiles/README.md) | Las normativas publicadas: un directorio por norma, un fichero por edición. |
| [`i18n/`](i18n/README.md) | Las traducciones de la prosa de la política (notas, categorías, vulnerabilidades, perfiles), un fichero por idioma. Lo que falte se muestra en inglés. |
