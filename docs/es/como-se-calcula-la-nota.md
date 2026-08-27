# Cómo se calcula la nota

Este documento es **el sistema de puntuación completo y público**. No hay
nada oculto: todos los números salen del fichero de política, que se puede
leer, exportar y cambiar.

Si lo que quieres es **cambiar** esos números, ve a
[`politica-puntuacion.md`](politica-puntuacion.md). Esto explica **cómo
funciona** y **por qué**, que es lo que necesita alguien a quien le acaba de
llegar una C y quiere saber si es justa.

## De dónde salen estos números (y de dónde no)

Conviene separar dos cosas, porque tienen orígenes distintos:

- **Qué algoritmo es bueno o malo** — que `aes256-cbc` sea *weak* o que
  `chacha20-poly1305@openssh.com` sea *recommended* — **sale de documentos**: un
  estándar que retira un algoritmo, un RFC, una ruptura publicada. Cada algoritmo
  lo dice en su nota, y la [auditoría de integridad](auditoria-integridad.md)
  rastrea de qué documento sale cada juicio.
- **Cómo esos juicios se convierten en una letra** — los pesos por clase
  (25/25/20/20/10), los modificadores en puntos, los umbrales de nota (A+…F) y
  los topes— **es criterio propio de esta herramienta**, no está tomado de
  ningún documento externo. Es una metodología: legítima, pero una **elección**.
  Por eso está escrita entera aquí y justificada número a número, para poder
  discutirla o cambiarla, no para confundirla con un requisito documentado. En el
  fichero de política, los bloques `categories` y `scoring` lo declaran así en su
  `_comment`.

La única cifra de puntuación que **sí** sale de un documento son las **bandas de
fuerza en bits** (192/128/112): son las de NIST SP 800-57 Part 1 Rev. 5, Tabla 2.
Los **nombres** de esas bandas (alta/moderada/heredada) son presentación propia.

---

## Dos respuestas, no una

La herramienta da **dos cosas distintas** sobre cada servidor y conviene no
confundirlas:

| | Qué es | Para qué sirve |
|---|---|---|
| **La nota** (`A+` … `F`) | Un número comprimido en una letra. | Comparar, seguir en el tiempo, poner en un panel. |
| **El veredicto** (`secure`, `acceptable`, `weak`, `insecure`) | Un juicio sobre el estado. | Decidir si hay que actuar. |

Se calculan por caminos distintos a propósito: **un promedio alto no borra una
cosa rota**. Pero no pueden contradecirse, y esa es la única regla que ata las
dos mitades:

> **Ningún servidor con veredicto `weak` puede tener una nota mejor que `C`, y
> ninguno con veredicto `insecure` puede tener mejor que `F`.**

Está comprobado contra los 96 servidores del laboratorio en cada ejecución de
la suite, no contra los cuatro casos que a alguien se le ocurrieron.

### La tabla de veredictos

| Veredicto | Cuándo |
|---|---|
| `secure` | Todo recomendado y con KEX estricto. |
| `acceptable` | Nada débil ni inseguro, pero algo mejorable. |
| `weak` | Algún algoritmo débil, material de clave corto, **o alguna vulnerabilidad crítica o alta confirmada**. |
| `insecure` | Algún algoritmo inseguro. |
| `unknown` | Se alcanzó el servidor pero la política no reconoce **nada** de lo que ofrece. |
| `error` | No se pudo escanear. |

Sobre `unknown`: si la política no clasifica ningún algoritmo del servidor, la
herramienta **no inventa una nota**. Devuelve `score` y `grade` a `null`, marca el
veredicto como `unknown` y emite un hallazgo indicando qué clases quedaron sin
evaluar. Dar una `F` haría pensar que el servidor es inseguro, y una `A` que es
correcto; ninguna está respaldada por la evidencia. Si solo algunas clases quedan
sin clasificar, sí se puntúa —los pesos se redistribuyen entre las evaluables—
pero el hallazgo avisa de que la nota es parcial.

Que el veredicto sea **independiente de la nota** importó por Terrapin: era la
única vulnerabilidad que el veredicto miraba, nombrada en el código y en ningún
sitio más, así que un servidor con una CVE crítica confirmada se resumía como
`secure` mientras la página de debajo decía lo contrario. Terrapin es una
coincidencia de severidad alta: ahora **todas pesan igual**, de lo que aquello era
un caso particular.

---

## Los cinco pasos

### 1. Cada algoritmo recibe una categoría

De las listas del fichero de política. Cada categoría vale unos puntos:

| Categoría | Puntos |
|---|---|
| `recommended` | 100 |
| `acceptable` | 75 |
| `weak` | 35 |
| `insecure` | 0 |
| `informational` | *no puntúa* |
| `unknown` | *no puntúa* |

**`unknown` no penaliza**, y es deliberado: los servidores ofrecen nombres que
nadie ha catalogado continuamente, y castigar por ellos trataría igual a quien
usa algo nuevo y bueno que a quien usa algo raro y malo. Sale en el informe
como «sin clasificar» para que alguien lo mire.

### 2. Cada clase se puntúa por **su peor algoritmo**

```
puntuación de la clase = mínimo de las puntuaciones de lo que ofrece
```

No es la media, y esto es lo que más sorprende. La razón es el propio
protocolo: **quien elige el algoritmo es el cliente**, entre los que el
servidor ofrece. Un servidor con doce cifrados excelentes y uno roto puede ser
llevado al roto por cualquier cliente mal configurado — o por quien esté en
medio. Ofrecerlo es permitirlo.

Las cinco clases son intercambio de claves (`kex`), clave de host
(`host_key`), cifrado (`cipher`), MAC (`mac`) y compresión (`compression`).

### 3. Las clases se combinan con sus pesos

| Clase | Peso |
|---|---|
| `kex` | 25 |
| `host_key` | 25 |
| `cipher` | 20 |
| `mac` | 20 |
| `compression` | 10 |

```
base = Σ (puntuación de la clase × peso) / Σ pesos
```

El intercambio de claves y la clave de host pesan más que el cifrado porque
son los que deciden si la sesión se puede **suplantar** o **descifrar después**
—incluido descifrarla dentro de diez años con lo que se grabe hoy—, mientras
que el cifrado solo decide qué tan difícil es leerla en directo. La compresión
pesa poco porque casi nunca está activada y su problema es acotado.

Una clase que no se pudo puntuar (todo desconocido) no entra en la media: ni
suma ni resta, y su peso sale del divisor.

### 4. Los modificadores suman o restan

Hechos que no son un algoritmo de una lista:

| Modificador | Puntos | Por qué |
|---|---|---|
| `missing_strict_kex` | −10 | Sin intercambio estricto de claves la transcripción del saludo no va autenticada, y se le pueden quitar mensajes sin que ninguno de los dos extremos lo note. |
| `no_post_quantum_kex` | −5 | Sin intercambio híbrido post-cuántico: exposición a «graba ahora, descifra después». |
| `host_key_below_minimum` | −25 | Una clave de host por debajo del mínimo. |
| `host_key_below_recommended` | −5 | Por debajo de lo recomendado. |
| `dh_group_below_minimum` | −15 | El grupo Diffie-Hellman negociado es menor que el mínimo. |

**Ninguna vulnerabilidad concreta aparece en esta tabla, y es deliberado.**
Hubo un modificador `terrapin_vulnerable` de −20: una CVE que movía el número
por llevar su nombre en el código, mientras las otras 64 no movían nada. Lo
que un servidor pierde por una vulnerabilidad lo deciden los topes, según su
**severidad**. Lo que sí queda aquí es la falta de intercambio estricto, que
es una propiedad de la negociación —como no ofrecer post-cuántico—, no una
CVE.

El resultado se recorta a `[0, 100]`.

> Una vulnerabilidad detectada **por versión** no mueve el número
> (`version_advisories_affect_score: false`). Una inferencia a partir de una
> cadena de versión no debería cambiar una nota. Para lo serio están los topes,
> que es el paso siguiente.

### 5. El número se convierte en letra, y luego bajan los topes

| Nota | Desde | Además exige |
|---|---|---|
| `A+` | 100 | intercambio estricto de claves, post-cuántico y claves de host correctas |
| `A` | 90 | |
| `B` | 80 | |
| `C` | 65 | |
| `D` | 50 | |
| `F` | 0 | |

Y después, **los topes**: condiciones que ponen un techo pase lo que pase con
el número.

| Si… | La nota no puede pasar de |
|---|---|
| Ofrece algo `insecure` | `F` |
| Ofrece algo `weak` | `C` |
| Una clave de host baja del mínimo | `D` |
| Hay una vulnerabilidad **alta o crítica** confirmada | `C` |
| Hay una crítica **medida** (no deducida de la versión) | `F` |
| Hay una crítica que el *changelog* del paquete **no** desmintió | `F` |

Los topes existen porque **un promedio miente**. Un servidor con veinte
algoritmos excelentes y uno roto tiene una media muy buena y un problema muy
grave.

---

## Las tres respuestas ante un CVE

Los tres últimos topes de la tabla son el mismo asunto visto con tres grados
de certeza, y merecen explicación porque es donde el sistema es más fino:

| Lo que se sabe | Nota máxima | Por qué |
|---|---|---|
| La versión anunciada coincide con un CVE alto o crítico, y nadie ha podido mirar el paquete | **C** | Es una pregunta abierta. Las distribuciones parchean sin cambiar el número de versión, así que no es una acusación — pero tampoco es una `A`. |
| Se pudo leer el *changelog* del paquete y **menciona** el arreglo | *sin tope* | La distribución dice que lo arregló. El hallazgo baja a informativo, con la línea del changelog citada. |
| Se pudo leer el *changelog* y **no** lo menciona | **F** | Ya no es una inferencia: el paquete no dice haberlo arreglado. |

Un detalle de diseño que el laboratorio corrigió sobre la marcha: hubo un
octavo tope, `any_critical_vulnerability` con techo `C`, y **sobraba**. Toda
crítica cuenta también como alta, y el tope de altas ya estaba en `C`, así que
no podía morder nunca por su cuenta. La suite lo detectó porque comprueba que
**todo tope que puede morder se ve mordiendo** en algún servidor del
laboratorio: un límite que no se dispara jamás es un límite decorativo.

Esto es lo mismo que hace la herramienta con las normativas, donde hay tres
respuestas y no dos: conforme, no conforme y **sin evaluar**. «No lo sé» es
una respuesta de pleno derecho, y decir `A` en su lugar es exactamente cómo
una herramienta de seguridad engaña a quien confía en ella.

> **Esto cambió.** Hasta agosto de 2026, una vulnerabilidad detectada por
> versión no ponía ningún techo salvo si se había leído el changelog. El
> resultado era que un Debian 11 con un CVE crítico confirmado sacaba **`A`**
> mientras su propio veredicto decía `weak`: dos mecanismos, la misma
> evidencia, conclusiones opuestas. En el laboratorio le pasaba a 4 de 96
> servidores.

---

## Un ejemplo completo, calculado de verdad

Un servidor sin intercambio estricto de claves y con un cifrado CBC entre los
que ofrece:

```
clases:  kex 100   host_key 100   cipher 35   mac 100   compression 100
pesos:   kex  25   host_key  25   cipher 20   mac  20   compression  10

base = (100×25 + 100×25 + 35×20 + 100×20 + 100×10) / 100 = 87

modificadores:
  missing_strict_kex    -10
  no_post_quantum_kex    -5
                       ----
final = 87 - 15 = 72

72 está en la banda de C (≥ 65)
topes: ofrecer algo 'weak' pone el techo en C, que es donde ya estaba
nota: C          veredicto: weak
```

Este ejemplo valía 52 y una D cuando existía un modificador
`terrapin_vulnerable` de −20. Al quitarlo, el mismo servidor sube a 72 y a C, y
la nota deja de depender de qué vulnerabilidad llevaba nombre propio en el
código. Lo que le sigue impidiendo pasar de C es el cifrado CBC, que es una
propiedad medida del servidor.

Fíjate en que **el cifrado CBC vale 35 y arrastra toda su clase a 35**, aunque
el servidor ofrezca además tres cifrados perfectos. Ese es el paso 2, y es el
que más nota cuesta.

Puedes reproducirlo con:

```bash
ssh-crypto-checker 127.0.0.1:2204 --format json -o informe.json
```

El objeto `score_breakdown` del JSON trae las puntuaciones por clase, los
pesos, la base, cada modificador aplicado y el resultado final. **No hay
aritmética que la herramienta no enseñe.**

---

## Qué hacer si no estás de acuerdo

Los números no son sagrados: son un fichero.

```bash
ssh-crypto-checker --export-policy mi-politica.json
$EDITOR mi-politica.json          # scoring.class_weights, scoring.modifiers…
ssh-crypto-checker --config mi-politica.json -f inventario.txt
```

Si tu organización considera que la compresión pesa más, o que no tener
post-cuántico todavía no debería restar, cámbialo y documenta por qué. Lo
único que no conviene es cambiarlo a mitad de una serie histórica sin volver a
escanear el parque: las notas dejarían de ser comparables entre sí.
