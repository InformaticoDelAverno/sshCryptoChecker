# `docs/` — manuales para extender la herramienta

El [README principal](README.md) explica cómo **usar** sshCryptoChecker.

Hay dos subdirectorios:

- `estandares/` — los documentos oficiales (NIST, BSI,
  BOE, ANSSI, IETF…) de los que salen los perfiles de conformidad, descargados
  de la web de su editor, con la URL de origen y la huella de cada uno.
- [`en/`](../en/README.md) — la documentación de usuario en inglés: el manual y
  estas mismas guías, traducidos. Los bloques de código son byte a byte los
  del original; la fuente de verdad es el español.
Estos manuales explican cómo **extenderlo**, y están escritos para que alguien
que no conoce el código pueda escribir un plugin o una política leyendo solo
esto.

Hay dos formas de extender la herramienta, y la primera pregunta es cuál te
toca:

> **¿Solo quieres entender por qué tu servidor sacó esa nota?** No necesitas
> ninguno de estos manuales: [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
> es el sistema de puntuación completo y público, con un ejemplo calculado
> paso a paso.

| Quieres… | Entonces | Manual |
|---|---|---|
| Cambiar qué algoritmos son buenos o malos, o qué nota saca cada cosa | Una **política**. No se toca Python. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| Detectar una vulnerabilidad conocida nueva | Casi siempre una **política**; solo si la detección necesita cálculo, un plugin. | [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) |
| Comprobar una directiva de `sshd_config` | Una **política**. | [`politica-configuracion.md`](politica-configuracion.md) |
| Medir contra una normativa (propia o publicada) | Una **política de normativa**. | [`politica-normativas.md`](politica-normativas.md) |
| Cambiar cómo se calcula la nota | Una **política**. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| Comprobar algo que requiere **código**: aritmética, correlación entre servidores, un formato que hay que analizar | Un **plugin**. | [`plugins.md`](plugins.md) |

> **La regla, en una frase:** si lo que quieres decir se puede escribir como un
> dato, escríbelo como un dato. El fichero de política se puede editar en un
> servidor a las tres de la mañana; un plugin hay que desplegarlo.

## Manuales de plugins

| Fichero | De qué trata |
|---|---|
| [`plugins.md`](plugins.md) | **Empieza aquí.** El contrato común a los tres tipos: dónde van los ficheros, qué metadatos hacen falta, qué recibe tu función, qué puede devolver, qué **no** puede hacer un plugin, y cómo probarlo. |
| [`plugin-check.md`](plugin-check.md) | Tipo `check`: mira **un** servidor. Es el 90 % de los casos. |
| [`plugin-fleet.md`](plugin-fleet.md) | Tipo `fleet`: mira **todos** los servidores del escaneo a la vez. Para lo que solo se ve comparando. |
| [`plugin-vulnerability.md`](plugin-vulnerability.md) | Tipo `vulnerability`: una vulnerabilidad conocida cuya detección no cabe en el fichero de política. |

## Manuales de políticas

| Fichero | De qué trata |
|---|---|
| [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) | **El sistema de puntuación, entero y público.** Cómo se llega de los algoritmos que ofrece un servidor a una letra, por qué pesa cada cosa lo que pesa, y la regla que impide que la nota y el veredicto se contradigan. |
| [`politicas.md`](politicas.md) | **Empieza aquí.** Qué es el fichero de política, cómo se saca una copia, dónde se busca, y las siete cosas que se pueden escribir en él. |
| [`politica-algoritmos.md`](politica-algoritmos.md) | Las cinco clases de algoritmo, sus entradas, sus patrones, sus categorías y sus etiquetas. |
| [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) | La gramática de detección completa: por versión, por algoritmo, por configuración, y cómo se combinan. |
| [`politica-configuracion.md`](politica-configuracion.md) | Comprobaciones sobre `sshd_config` y sobre el `ssh_config` del cliente. |
| [`politica-puntuacion.md`](politica-puntuacion.md) | Pesos, modificadores, escala de notas, **topes de nota** y bandas de fuerza de seguridad. |
| [`politica-normativas.md`](politica-normativas.md) | Perfiles de conformidad: los dos tipos, y una edición por fichero. |

## Uso avanzado y desarrollo

| Fichero | De qué trata |
|---|---|
| [`uso-avanzado.md`](uso-avanzado.md) | Comparar con un escaneo anterior, auditar el cliente, escanear tras un bastión, el fichero de inventario y credenciales, y las comprobaciones remotas (SSHFP, `known_hosts`, gracia de login…). |
| [`desarrollo.md`](desarrollo.md) | La estructura del código, la cobertura end-to-end y sus dos cierres, el *testing* de mutación, cómo añadir una comprobación o un formato de salida, y el estilo. |

## Auditoría

| Fichero | De qué trata |
|---|---|
| [`auditoria-integridad.md`](auditoria-integridad.md) | **¿Todo lo que afirma la herramienta sale de un documento?** Auditoría (2026-08-13) de los 25 perfiles y de la política base contra los documentos de `estandares/`: qué está respaldado, qué se apoya en documentos aún sin archivar, y qué es metodología propia. |
