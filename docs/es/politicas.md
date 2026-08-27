# Manual del fichero de política — visión general

El fichero de política es **el criterio de la herramienta escrito como datos**.
Qué algoritmo es bueno, qué vulnerabilidad existe, cuánto pesa cada cosa en la
nota, qué exige cada normativa: todo eso se edita sin tocar Python.

La razón es práctica. Lo que hoy es seguro mañana puede no serlo, y actualizar
la herramienta debe ser **editar un JSON**, no desplegar una versión nueva.
Alguien tiene que poder cambiar el criterio en un bastión, a las tres de la
mañana, sin un entorno de desarrollo.

---

## Sacar una copia y usarla

```bash
ssh-crypto-checker --export-policy mi-politica.json
ssh-crypto-checker --config mi-politica.json servidor.example.com
```

`--export-policy` escribe **el fichero y su directorio `profiles/` al lado**,
porque una política sin normativas no da error: se parece exactamente a un
escaneo contra normativas que todo el mundo cumple. Los dos viajan juntos.

Se niega a sobrescribir lo que ya está. Una segunda exportación al mismo
directorio sí está permitida (una política estricta y otra laxa compartiendo
un juego de normativas es la forma que tiene el propio árbol instalado); lo que
se rechaza es pisar un fichero de normativa **que dice otra cosa**, y el
rechazo ocurre antes de escribir nada.

## Dónde se busca, en orden

1. Lo que diga `--config`.
2. La variable de entorno `SSH_CRYPTO_CHECKER_CONFIG`.
3. `./ssh-crypto-checker.json`, en el directorio actual.
4. `~/.config/ssh-crypto-checker/algorithms.json`
5. `/etc/ssh-crypto-checker/algorithms.json`
6. La copia que trae el paquete.

`--show-policy` dice cuál se está usando y enseña el orden con un asterisco en
la ganadora. Una política **fijada por la variable de entorno y que no existe
es un error**, no una vuelta silenciosa a la de serie: fijar una política tiene
que significar que se usó esa.

## Formatos

JSON siempre. TOML si el intérprete es 3.11 o más nuevo, y YAML si está
instalado PyYAML — en ambos casos, si no se puede, el mensaje lo dice en vez de
fallar de forma rara.

---

## Las siete cosas que hay dentro

| Clave | Qué define | Manual |
|---|---|---|
| `algorithms` | Las cinco clases de algoritmo, con sus entradas, patrones, categorías y etiquetas. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| `categories` | Qué significa cada categoría (`recommended`, `weak`, `insecure`…) y cuántos puntos vale. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| `vulnerabilities` | Las vulnerabilidades conocidas y cómo se detecta cada una. | [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) |
| `sshd_config_checks` / `ssh_config_checks` | Comprobaciones sobre directivas del servidor y del cliente. | [`politica-configuracion.md`](politica-configuracion.md) |
| `scoring` | Pesos por clase, modificadores, escala de notas y **topes de nota**. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `requirements` y `security_strength` | Tamaños mínimos de clave y las bandas de fuerza en bits. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `profiles/` (directorio) | Las normativas: una por directorio, una edición por fichero. | [`politica-normativas.md`](politica-normativas.md) |

Además: `schema_version` (debe empezar por `1.`), `metadata` (lo que
`--show-policy` enseña sobre el origen del fichero) y `tag_labels`, que da
nombre legible a cada etiqueta.

---

## Cómo se comprueba lo que escribes

**El cargador es estricto a propósito y dice siempre qué clave está mal.** Un
fichero de tres mil líneas no se depura por bisección:

```
mi-politica.json: vulnerabilities[7].detection: unknown condition 'presnt'
```

Reglas que sorprenden y son deliberadas:

- **Las cinco clases de algoritmo son obligatorias.** Borrar una no significa
  «no me importa esa clase», significa que un servidor podría ofrecer lo que
  fuera ahí sin que nadie dijese nada.
- **La escala de notas no puede estar vacía.**
- **Un identificador duplicado se rechaza**: dos detecciones con el mismo `id`
  no se pueden informar las dos.
- **Un `when` de tope de nota que no existe se rechaza**, con la lista de los
  que sí. Un tope que nunca se dispara por una errata es peor que no tenerlo.
- Un **algoritmo que la política no conoce** no es un error: los servidores
  ofrecen nombres que nadie ha catalogado continuamente. Sale como
  *desconocido*, que es una respuesta.

Prueba siempre lo que edites antes de confiar en ello:

```bash
ssh-crypto-checker --config mi-politica.json --show-policy
ssh-crypto-checker --config mi-politica.json --list-vulnerabilities
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --no-color
```

---

## La regla que no conviene romper

**No inventes contenido.** Si añades una vulnerabilidad, pon la referencia
real. Si codificas una normativa, léela primero. Un fichero de política con
entradas inventadas produce informes que alguien va a creerse, y el daño no lo
paga quien lo escribió.
