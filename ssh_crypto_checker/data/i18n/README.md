# `ssh_crypto_checker/data/i18n/` — la política en otros idiomas

La política (`../algorithms.json`) y las normativas (`../profiles/`) están
escritas en inglés. Aquí vive su prosa traducida: las notas de cada algoritmo,
las descripciones de categoría y de nivel de fuerza, las etiquetas, las
vulnerabilidades, las comprobaciones de configuración y los resúmenes de
perfil.

Cada fichero es un *overlay* para un idioma, y `load_policy(language=...)` lo
aplica sobre la política ya cargada. Está **indexado por identificadores
estables** (el nombre del algoritmo, la clave de categoría, el `id` de la
vulnerabilidad o del nivel, el id del perfil), no por posición, así que:

- se aplica a cualquier política, no solo a la incorporada;
- lo que el overlay no menciona se queda **en inglés** — es siempre el
  respaldo, y un overlay a medias es válido;
- los identificadores técnicos y las citas (nombres de algoritmo, CVE, RFC,
  normas, opciones de `ssh-keygen`) se dejan **tal cual** en la traducción.

El idioma por defecto es el inglés (no hay `policy.en.json`: el inglés es el
propio `algorithms.json`).

## Ficheros

| Fichero | Qué contiene |
|---|---|
| `algorithms.es.json` | La prosa de la política en español de España. Nombrado como el fichero que traduce (`algorithms.json`). |
