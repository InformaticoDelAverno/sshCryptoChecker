# Manual de política — puntuación, notas y topes

> Antes de esto, lee [`politicas.md`](politicas.md).

Aquí se decide **qué nota saca un servidor**. Es la parte con más
consecuencias del fichero: cambiar un peso cambia todos los informes.

---

## Cómo se calcula, en orden

1. **Cada clase de algoritmo saca una puntuación** a partir de las categorías
   de lo que el servidor ofrece.
2. **Se combinan con los pesos** de `class_weights`.
3. **Se aplican los modificadores**, que suman o restan puntos por hechos que
   no son un algoritmo.
4. **El número resultante se convierte en nota** con la escala de `grades`.
5. **Se aplican los topes**: una condición de `grade_caps` puede bajar la nota
   por mucho que el número diga otra cosa.

El veredicto (`seguro`, `aceptable`, `débil`, `inseguro`) se decide **aparte**
del número. Un servidor puede sacar buen número y tener un veredicto malo:
eso es deliberado, porque un promedio alto no borra una cosa rota.

---

## Los pesos

```json
"class_weights": { "kex": 25, "host_key": 25, "cipher": 20, "mac": 20, "compression": 10 }
```

No tienen que sumar 100; se normalizan. Lo que dice esta tabla es qué importa
más: aquí, el intercambio de claves y la clave de host valen cada uno más que
el cifrado, porque son los que deciden si la sesión se puede suplantar o
descifrar después.

---

## Los modificadores

Puntos que se suman o restan por hechos que no salen de la lista de
algoritmos:

```json
"modifiers": [
  { "id": "missing_strict_kex",         "points": -10, "description": "..." },
  { "id": "no_post_quantum_kex",        "points":  -5, "description": "..." },
  { "id": "host_key_below_minimum",     "points": -25, "description": "..." },
  { "id": "host_key_below_recommended", "points":  -5, "description": "..." },
  { "id": "dh_group_below_minimum",     "points": -15, "description": "..." }
]
```

Los `id` son los que la herramienta sabe calcular; uno inventado no hace nada.
Lo que sí puedes cambiar libremente es **cuántos puntos** vale cada uno, que es
donde vive el criterio.

`"version_advisories_affect_score": false` dice que una vulnerabilidad
detectada **por versión** no mueve el número. Es la postura prudente: una
inferencia a partir de un número de versión no debería cambiar una nota, y
para lo grave ya están los topes.

---

## La escala de notas

```json
"grades": [
  { "grade": "A+", "min_score": 100, "requires": ["strict_kex", "post_quantum", "host_keys_ok"] },
  { "grade": "A",  "min_score": 90 },
  { "grade": "B",  "min_score": 80 },
  { "grade": "C",  "min_score": 65 },
  { "grade": "D",  "min_score": 50 },
  { "grade": "F",  "min_score": 0 }
]
```

Se recorre de arriba abajo y gana la primera cuyo `min_score` se alcanza.
`requires` añade condiciones que **además** hay que cumplir: aquí, un A+ exige
intercambio estricto de claves, intercambio post-cuántico y claves de host
correctas, por muy alto que sea el número.

La lista **no puede estar vacía**: sin escala no hay nota, y el cargador lo
rechaza.

---

## Los topes de nota

Un tope dice: **pase lo que pase con el número, esta nota no puede subir de
ahí.**

```json
"grade_caps": [
  { "when": "any_insecure_algorithm", "max_grade": "F" },
  { "when": "any_weak_algorithm",     "max_grade": "C" },
  { "when": "any_high_vulnerability", "max_grade": "C" },
  { "when": "host_key_below_minimum", "max_grade": "D" },
  { "when": "any_measured_critical_vulnerability", "max_grade": "F" },
  { "when": "any_critical_vulnerability_the_changelog_did_not_clear", "max_grade": "F" }
]
```

Existen porque un promedio miente. Un servidor con veinte algoritmos
excelentes y uno roto tiene un promedio muy bueno y un problema muy grave. El
tope corta esa aritmética.

### Las condiciones que se pueden usar

| `when` | Se cumple cuando |
|---|---|
| `any_insecure_algorithm` | Ofrece algo de categoría `insecure`. |
| `any_weak_algorithm` | Ofrece algo de categoría `weak`. |
| `host_key_below_minimum` | Una clave de host baja del mínimo. |
| `any_critical_vulnerability` | Cualquier vulnerabilidad crítica, incluidas las inferidas por versión. |
| `any_high_vulnerability` | Ídem, con severidad alta. |
| `any_measured_critical_vulnerability` | Una crítica **medida en el servidor**, no deducida de un número de versión. |
| `any_critical_vulnerability_the_changelog_did_not_clear` | Una crítica que la auditoría del *changelog* **no** desmintió. Un servidor parcheado por la distribución no queda castigado. |

> **Un `when` que no existe se rechaza al cargar**, con la lista de los
> válidos. Un tope que no se dispara nunca por una errata es peor que no
> tenerlo: pareces protegido y no lo estás.

Las dos últimas condiciones son las que conviene entender. `any_critical_vulnerability`
castiga a un servidor cuya distribución ya retroportó el arreglo; las otras
dos no. Elige según lo que quieras: rigor máximo o precisión.

---

## Fuerza de seguridad efectiva

Aparte de la nota, la herramienta informa de **cuántos bits de seguridad
efectivos** tiene la conexión: el eslabón más débil de la cadena.

```json
"security_strength": {
  "reference": "NIST SP 800-57 Part 1 Rev. 5",
  "url": "https://doi.org/10.6028/NIST.SP.800-57pt1r5",
  "modulus_strength": [ [15360, 256], [7680, 192], [3072, 128], [2048, 112] ],
  "levels": [
    { "id": "high",     "minimum_bits": 192, "label": "High",     "description": "..." },
    { "id": "moderate", "minimum_bits": 128, "label": "Moderate", "description": "..." }
  ]
}
```

- **`modulus_strength`** traduce el tamaño de un módulo RSA o Diffie-Hellman a
  bits de seguridad. Son pares `[bits_de_módulo, bits_de_seguridad]`, y se
  aplica el mayor que no pase del tamaño observado.
- **`levels`** son las bandas con las que se etiqueta el resultado. Se ordenan
  solas por `minimum_bits`.

Los bits por algoritmo salen de `security_strength_bits` en cada entrada, que
se documenta en [`politica-algoritmos.md`](politica-algoritmos.md).

---

## Antes de tocar nada de esto

Cambiar los pesos o los topes cambia **todos** los informes que produzcas, y
los históricos dejarán de ser comparables. Si mantienes una serie temporal:

1. Cambia la política.
2. Vuelve a escanear el parque entero con la nueva.
3. Empieza la serie desde ahí, y anota por qué.

Y compruébalo contra el laboratorio, que tiene servidores en cada escalón:

```bash
for puerto in 2222 2223 2224 2225; do
  ssh-crypto-checker --config mi-politica.json 127.0.0.1:$puerto -q --no-color | head -3
done
```
