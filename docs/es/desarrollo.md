# Manual de desarrollo

> El mapa del repositorio y las guías de usuario están en [`README.md`](README.md).

## Estructura

```
ssh_crypto_checker/
├── cli.py             Interfaz de línea de comandos y códigos de salida
├── targets.py         Análisis de objetivos (host:puerto, IPv6, ficheros)
├── ssh_protocol.py    Capa de transporte SSH: banner, KEXINIT, claves de host
├── crypto/            Primitivas mínimas para completar un intercambio
│   ├── x25519.py      X25519 (RFC 7748)
│   ├── ecc.py         Curvas NIST P-256/384/521
│   └── dh.py          Grupos MODP 1 y 14 (RFC 2409/3526)
├── policy.py          Carga y validación del fichero de políticas
├── models.py          Dataclasses compartidas y serialización a JSON
├── analysis.py        Clasificación, hallazgos, puntuación y recomendaciones
├── scanner.py         Orquestación concurrente
├── reporting/         Un renderizador por formato
│   ├── common.py      Colores, tablas, ajuste de texto
│   ├── console.py     Terminal (y bloques reutilizados por text.py)
│   ├── text.py        Texto plano
│   ├── json_report.py JSON
│   └── html.py        HTML autocontenido
└── data/
    └── algorithms.json  La política por defecto
```

Flujo de datos:

```
targets.py  ->  scanner.py  ->  ssh_protocol.py   (red)
                     |
                     v
                analysis.py + policy.py           (juicio)
                     |
                     v
                 models.py                        (TargetResult)
                     |
                     v
                reporting/*                       (presentación)
```

Reglas de diseño que conviene respetar:

- **Cero dependencias en tiempo de ejecución.** Debe funcionar con el Python de
  cualquier distribución.
- **Ninguna decisión de seguridad en el código.** Si estás escribiendo el nombre
  de un algoritmo dentro de un `.py`, probablemente debería estar en
  `algorithms.json`. Las excepciones legítimas son
  `ssh_protocol._CLIENT_CIPHERS` (lo que el escáner *ofrece* para que la
  negociación funcione, deliberadamente amplio) y `_SUPPORTED_KEX` /
  `_PQ_KEX_CLIENT_BYTES` (lo que el escáner sabe ejecutar).

### Servidores solo post-cuánticos

Un servidor que solo ofrece ML-KEM o sntrup761 no se puede negociar con
criptografía clásica, y hasta ahora eso significaba **ninguna clave de host**:
sin huella, sin tamaño, sin certificado, sin comparación con SSHFP.

No hace falta implementar el KEM para arreglarlo. El servidor pone su clave de
host **como primer campo de la respuesta**, antes del criptograma y antes de la
firma, así que basta con que conteste. Y contesta si el cliente le manda una
clave *bien formada*: FIPS 203 solo exige que los coeficientes de 12 bits sean
menores que q, y eso se consigue eligiendo los coeficientes en vez de los
bytes. Con bytes al azar la probabilidad de pasar la comprobación es
(3329/4096)^768, o sea cero.

Nadie tiene la clave privada correspondiente y no existe: esto compra una
respuesta, no una sesión. Por eso el método post-cuántico va **el último** en el
orden de preferencia —si hay uno clásico se usa ese, que sí da secreto
compartido— y por eso el código se niega explícitamente a seguir cuando alguien
le pide una sesión autenticada sobre él, en lugar de montar una que descifraría
a ruido. La huella obtenida así se compara en los tests con la del intercambio
clásico contra un servidor que ofrece los dos.
- **Los renderizadores no juzgan.** Reciben un `TargetResult` ya analizado y
  solo lo presentan. Toda la lógica vive en `analysis.py`.
- **Los errores de un objetivo no abortan el escaneo.** `scan_target` captura
  sus propias excepciones y devuelve un resultado con `status=error`.

## Cobertura de los tests end to end

```bash
pip install coverage        # única dependencia de desarrollo; la herramienta no tiene ninguna
python3 -m coverage run --branch --source=ssh_crypto_checker -m unittest tests.test_docker_lab
python3 -m coverage report -m
```

**Se miden dos cosas por separado, y responden a preguntas distintas.**

| Medición | Cómo | Qué responde | Cifra |
|---|---|---|---|
| Suite completa | `-m unittest discover -s tests -t .` | Cuánto del código ejecuta *algún* test | **100%** |
| Solo el laboratorio | `-m unittest tests.test_docker_lab` | Cuánto se ha ejecutado **contra servidores SSH de verdad** | **~90%** (642 sentencias y 132 ramas sin alcanzar, listadas una a una) |

La primera es **100% de sentencias y 100% de ramas, sin una sola exclusión**:
`.coveragerc` no tiene `exclude_also` ni `exclude_lines`. No hay nada en ese
fichero que le diga a coverage que mire hacia otro lado.

La segunda es la exigente, y es la que ha encontrado los fallos. Pasar toda la
suite infla el número con tests unitarios contra dobles; un camino que sólo un
doble ha recorrido no es un camino que se sepa que funciona contra un servidor.
De las sentencias que le faltan, **cada una está justificada abajo una por una**
y con la comprobación al lado, no por categorías.

Medirlo dejó a la vista el hueco más grande que quedaba: **la línea de comandos
estaba al 0%**. Los tests end to end llamaban a `scan()` directamente, así que
el análisis de argumentos, el fichero de inventario, la escritura de cada
formato, la comparación con una línea base, el histórico y **los códigos de
salida** —lo que usa cualquiera que scriptee esto— solo se probaban contra
dobles. Ahora hay una clase que conduce la CLI real contra el laboratorio.

Lo mismo pasaba por debajo: el escáner implementa AES-CTR, AES-GCM,
ChaCha20-Poly1305 y CBC porque tiene que **cifrar paquetes de verdad** para leer
los métodos de autenticación, y todos los servidores auditables aceptaban
`aes256-ctr`. Las otras tres transformaciones solo se probaban contra vectores
conocidos, nunca contra un servidor que rechazaría una respuesta incorrecta. Hay
tres servidores más que ofrecen una sola cifra cada uno.

**`.coveragerc` ya no tiene lista de exclusiones, y ese es el objetivo.** Una
exclusión es un trozo de código que nadie ha ejecutado nunca, con una nota al
lado que dice que no hay que preocuparse. Las que había desaparecieron una a
una: algunas porque la guarda era redundante, otras porque el código se
reestructuró para que la comprobación *sea* el bucle en vez de una rama al lado
—en `crypto/x25519.py` el último intercambio condicional resultó estar muerto
bajo el *clamping*—, y el resto porque eran perfectamente alcanzables en cuanto
alguien lo intentó: un intérprete sin `tomllib`, un flujo ya cerrado, un `ssh`
que ignora `SIGTERM`.

**El umbral (`fail_under`) en `.coveragerc` está en 100**, porque la cifra
está en 100. `coverage report` falla si baja, así que un cambio que deje de
ejercitar un camino se nota al momento y no un año después. Bajarlo pide una
explicación en el mensaje del commit.

### Y la segunda cifra tiene su propio cierre

Un umbral sobre el porcentaje no habría servido para la medición del
laboratorio: **82 sentencias de 6745 pueden convertirse en 120 sin que el 98%
se mueva**. Así que lo que se guarda no es el porcentaje, sino **la lista
exacta de líneas que el laboratorio no alcanza**, en
`tests/lab-coverage-baseline.json`, identificadas **por su texto** y no por su
número —el número se mueve con la primera edición, y una línea base que hay que
regenerar cada dos por tres enseña a regenerarla sin leerla—.

```bash
python3 -m coverage run --rcfile=.coveragerc -m unittest tests.test_docker_lab
python3 -m coverage json --rcfile=.coveragerc --fail-under=0 -o coverage-lab.json
python3 tools/lab_coverage_gate.py
```

Falla en las dos direcciones, y eso es lo importante:

| Lo que pasa | Qué hace el cierre |
|---|---|
| Aparece una línea que el laboratorio no alcanza | **Falla**, y la nombra. O se le da al laboratorio una forma de llegar, o entra en la lista **con su motivo en este README** |
| Una línea de la lista pasa a estar cubierta | **También falla**. Una lista con permisos que ya nadie usa deja de ser cierta, y taparía a la siguiente línea que se escribiera igual |

Encima hay un techo escrito en `tests/test_coverage_gates.py`
(`MAX_UNREACHED_STATEMENTS`, `MAX_UNREACHED_BRANCHES`): bajarlo no cuesta nada,
subirlo obliga a tocar un test y a decir por qué en el commit. Ese fichero
comprueba además que `.coveragerc` sigue con `fail_under = 100`, con ramas, y
**sin lista de exclusiones** —la afirmación más fuerte de esta sección, que sin
nadie vigilándola es la primera que se pierde—, y que cada línea de la lista
base **sigue existiendo** en el fichero que dice.

Y prueba el propio cierre con una medición falsificada en las dos direcciones,
porque un cierre que nadie prueba es un cierre que siempre dice que sí.

### El laboratorio también ejecuta la herramienta, no solo la apunta

Todo lo demás aquí apunta el escáner a un servidor. Hay un contenedor
(`lab/runner/Dockerfile`) que hace lo contrario: **ejecuta el escáner**, con
el repositorio montado dentro. Es la única forma de que el laboratorio controle
el **entorno** en vez del servidor — una máquina sin servidor de nombres, una
cuyo `/etc/resolv.conf` no se puede leer, una instalación a la que le falta su
propio fichero de política. Nada de eso se puede montar desde la máquina que
corre los tests: el proceso no puede sustituir `/etc/resolv.conf`, y necesita
el fichero de política que el tercer caso quita.

Lleva **Python 3.12 a propósito, no el más nuevo**. Desde 3.14 las anotaciones
se evalúan de forma perezosa (PEP 649); antes se evalúan al definir la función.
Una anotación que nombra un tipo que nadie importó es invisible en 3.14 y un
`NameError` en todo lo anterior — y el cargador responde a eso **descartando la
comprobación**, imprimiendo una línea de aviso y siguiendo. Dos comprobaciones
*builtin* estaban exactamente así, una de ellas la clasificación de algoritmos
de severidad *critical*: en el Python que tiene un usuario de verdad, la
herramienta reportaba de menos y lo decía de pasada. Este contenedor es lo más
viejo del laboratorio y está aquí para seguir diciéndolo.

### Que una línea se ejecute no quiere decir que alguien la mire

Coverage registra que el intérprete pasó por una línea, no que nadie se
enteraría si esa línea hiciera otra cosa. Un 100% construido con líneas así
no protege de nada, así que hay una segunda pregunta y una herramienta que la
responde:

```bash
python3 tools/mutation_gate.py            # comprobar contra la línea base
python3 tools/mutation_gate.py --update   # anotar lo que sobrevive ahora
python3 tools/mutation_gate.py --only policy   # un módulo, mientras trabajas
```

Rompe el código a propósito, un cambio pequeño cada vez, y ejecuta los tests.
Lo que hace fallar a un test está **muerto**: alguien vigilaba. Lo que nadie
nota **sobrevive**, y es una línea que la suite visita sin mirar.

| El cambio | Y es un fallo de verdad |
|---|---|
| `<` pasa a `<=` | un error de uno en un límite |
| `==` pasa a `!=` | una condición invertida |
| `and` pasa a `or` | una guarda ensanchada |
| `0` pasa a `1` | un valor por defecto cambiado |
| `+` pasa a `-` | un desliz aritmético |
| **desaparece un `raise`** | un error tragado: entrada mala aceptada, política rota cargada, paquete malformado leído como si tuviera sentido |
| **un `return` devuelve `None`** | una respuesta olvidada: quien la use se entera, quien la ignore nunca la usó |

Lo que encontró, la primera vez que se ejecutó de verdad: **nada comprobaba
que una clave de host por debajo del mínimo levantara la bandera** que topa la
nota en D. Ni que una clave ilegible *no* contara como pequeña. Ni que un grupo
Diffie-Hellman de exactamente el mínimo no fuera débil. Ni las tres condiciones
exactas de la palabra `secure`, que nadie había separado. Catorce huecos en el
cálculo de la nota, todos ejecutados por la suite y ninguno mirado.

**Dos advertencias, las dos aprendidas equivocándose:**

Un mapeo de fichero fuente a módulo de tests —que estaba ahí por velocidad— es
una invitación a equivocarse **en la dirección que halaga**. Los vectores
FIPS-197 viven en `test_remote_checks.py`, no en `test_crypto.py`, así que los
mutantes de AES los juzgaban tests que no tocan el cifrado y cincuenta y dos
«sobrevivían». No hay mapeo: cada mutante se enfrenta a la suite entera, y el
paralelismo compra la velocidad que el mapeo intentaba comprar.

**Dónde está hoy:** 3508 mutantes, 3475 muertos, 33
supervivientes. Ese 33 hay que leerlo con su historia, porque el número que
había antes era **cero, y el cero era mentira dos veces**. La primera: la puerta
copiaba al aislado dos directorios y la suite necesitaba más, así que veinte
pruebas erraban en todos los aislados y **todo** mutante se anotaba como cazado;
arreglarla convirtió aquel cero en 748, y de ahí bajó de verdad hasta 443. La
segunda, más sutil: la puerta reutilizaba el aislado entre mutantes **sin
`-B`**, y en un `/tmp` sobre ext3 una edición del mismo tamaño (`==`↔`!=`,
`+0`↔`-0`, `and`↔`or`, un dígito por otro) deja intactos fecha y tamaño, así que
CPython corría el `.pyc` viejo y la mutación **nunca se ejecutaba** — y un plazo
demasiado corto anotaba como caza una suite lenta pero que pasaba. Con `-B` y
600 segundos la pasada rápida es determinista, y la cifra honesta no es cero: la
suite mata 3475 de 3508, y los 33 que quedan **no cambian nada que un llamador
pueda observar** — una comparación con guarda, un término de peso cero, un
`maxsplit` que se lee en `[0]`, coordenadas proyectivas de la escalera de
Montgomery, un bloque de flujo de clave que se descarta, un `-> bool` que solo
se usa por su verdad —. Cada uno está **probado equivalente** por diferenciación
exhaustiva o por fuzz a través de la función real, y los 33 están listados por
fichero y línea en `tests/mutation-baseline.json`; el cierre falla en cuanto
aparezca el superviviente número 34.

Que estas tres cifras sigan siendo ciertas no depende de que alguien se acuerde
de editarlas: `tests/test_documentation_matches_the_policy.py` las lee de este
parrafo y las compara con el fichero de supervivientes y con la constante del
cierre.

Eso no quiere decir «los tests son perfectos». Quiere decir exactamente lo que
mide: **ninguno de los siete cambios que sabe hacer —una comparación, un
`and`, un booleano, una constante, una operación aritmética, un `raise` que
desaparece, un `return` que devuelve `None`— sobrevive**. Lo que no mide:
cambios más grandes, cadenas de texto y llamadas sustituidas.

Tarda **171 minutos**, y por eso avisa de dónde va cada cien mutantes: una
herramienta que no imprime nada durante tres horas es una herramienta que la
gente mata, y entonces es una herramienta que nadie ejecuta.

**Y el laboratorio tiene la última palabra.** Un candidato a superviviente
—algo que la suite unitaria no mató— se le pasa a `DockerLabTests`, que
escanea los 95 servidores con todas las sondas en 18 segundos, antes de
escribirlo en la lista. No corre para cada mutante, solo para los que llegan
vivos, que es el único sitio donde puede cambiar la respuesta: un superviviente
tiene que significar «no lo caza nada», no «no lo caza la mitad rápida». Hoy no
llega ninguno, así que no cuesta nada.

> Honestamente: **todavía no ha cazado nada que la suite unitaria dejara
> pasar**. Se probaron tres mutaciones elegidas para favorecerlo —el formato
> que pide el script remoto, un marcador de sección, el limpiador del banner—
> y las tres las cazaron también los tests unitarios. Está ahí como seguro, no
> como mejora demostrada.

Y un superviviente se **confirma con la máquina tranquila** antes de creérselo.
Catorce suites en paralelo es exactamente cómo un test que habría cazado algo
se queda sin tiempo, y un cierre que da falsas alarmas es un cierre que la
gente aprende a ignorar.

En CI hay dos trabajos. `coverage:gates` cuesta segundos y corre **en cada
push**: comprueba `.coveragerc`, la lista base y el propio cierre. `coverage:lab`
levanta el laboratorio entero y hace las dos mediciones —la del laboratorio
contra su lista base, y la de la suite completa contra `fail_under = 100`—;
como son unos 130 contenedores y la mayoría se compilan, va **a mano o por
planificación**, no en cada push.

Lo que la lista de exclusiones decía que era inalcanzable resultó no serlo, y
perseguirlo encontró fallos:

| Lo que decía la exclusión | Lo que pasó al quitarla |
|---|---|
| Validación de la política (`policy.py`) | Se alcanza con `--config` y un fichero roto. Apareció que un `entries` con el tipo equivocado reventaba con `AttributeError` en vez de `PolicyError` |
| Errores del cargador de plugins | Se alcanzan con un directorio de plugins rotos: `lab/lab-plugin-broken` tiene un fichero por motivo. Un directorio llamado `algo.py` salía como `IsADirectoryError` |
| `except Exception` en el pool de hilos | Se prueba simulando el defecto que contiene. Se quitó por "inalcanzable" y la siguiente ejecución perdió un escaneo de 41 servidores por un `NameError` de una línea |
| Detección de terminal en `reporting/common.py` | Se alcanza asignando un pty al test |

El código que contiene defectos no se alcanza con ninguna *entrada*, pero sí se
prueba **simulando el defecto**. Que no exista una entrada que lo dispare no es
lo mismo que no poder probarlo.

### Lo que el laboratorio no puede alcanzar, y por qué

Cada línea que queda se ha revisado **una a una**, no por categorías, y el
motivo está comprobado donde se podía comprobar. Lo que en su día figuraba
aquí como inalcanzable y hoy está cubierto ocupa ya más sitio que lo que
queda:

| Lo que esta lista decía | Lo que resultó ser |
|---|---|
| Una sesión cifrada hostil «exigiría implementar SSH entero» | Exige bastante menos, porque el escáner es un escáner: **no verifica la firma de la clave de host**, así que un servidor de laboratorio necesita una curva, un calendario de claves y una cifra, y puede firmar con bytes al azar. `lab/exotic/session_server.py` son 380 líneas y cubre las tres respuestas a la petición de autenticación |
| El reset llega como fin de fichero «por una carrera» | No era una carrera: era el proxy de Docker, que termina la conexión al publicar un puerto y entrega un final ordenado hiciera lo que hiciera el contenedor. Veinte de veinte contra un socket local, **cero de diez por el puerto publicado**, seis de seis contra la dirección del contenedor |
| El tope de conexiones no se puede agotar | Sí: un servidor que cierra su escucha mientras está lleno rechaza la conexión en vez de aceptarla y callar. Otra vez sólo se ve hablando al contenedor directamente |
| Un informe sin nada que informar no existe en el laboratorio | Existe con una política sin reglas y un servidor post-cuántico: nota A+, cero hallazgos |
| `to_jsonable` no ve nunca unos `bytes` | Los ve si un plugin los mete. Preguntar de dónde podían venir encontró que **cuatro formatos reventaban** al escribirlos |
| El sondeo de autenticación no puede quedarse sin secreto compartido | Puede: X25519 no tiene codificación que rechazar, así que un valor público de 31 bytes no lanza nada — simplemente no hay secreto |
| Cuatro más, ya en la revisión anterior | El tope de sondeos de clave de host, un secreto compartido de cero, el reloj de la medición de gracia y el ajuste de línea de un texto vacío |
| «La validación de argumentos de una primitiva no la alcanza ningún servidor» | Cierto para claves, IV y contadores. **Falso para la longitud de un paquete CBC**, que viaja cifrada y la elige el par: veinte deja ocho, y ocho no es un bloque |
| «El contrato de los plugins no lo puede crear el laboratorio» | `analyse()` para antes de ejecutar una comprobación sin oferta, en *ese* camino. La **vista de flota** guarda una vista por cada resultado, incluidos los que fallaron: sin oferta y sin valoración. Un plugin de flota que reutiliza las comprobaciones builtin conduce justo esa vista |
| «El proceso de test no puede sustituir `/etc/resolv.conf`» | No puede. **Un contenedor sí**, y ahora el laboratorio tiene uno que ejecuta la herramienta en vez de recibirla. Tres líneas del entorno alcanzadas con la CLI de verdad — y de paso apareció que dos comprobaciones *builtin* no cargaban en ningún Python anterior al 3.14 |

Lo que queda, con el motivo comprobado:

| Grupo | Ejemplo | Por qué el laboratorio no llega, y cómo se comprobó |
|---|---|---|
| Validación de argumentos de las primitivas | `raise ValueError("AES keys are 16, 24 or 32 bytes long")` | Los tamaños de clave, bloque, IV y contador **los deriva el escáner** del hash de intercambio. Un servidor no elige ninguno. **Salvo uno**: la longitud de un paquete CBC viaja cifrada, la elige el par y tiene que dejar un número entero de bloques — hay un servidor que dice veinte y deja ocho, y esa línea ya no está aquí |
| **La verificación de firmas DNSSEC** | `dnssec.py`, `crypto/{ec,ecdsa,ed25519,rsa}.py` | El `lab-dns` **nunca firma** —es el estado normal en internet, y merece un aviso—, así que ninguna RRSIG se verifica contra él: la validación de la cadena y las cuatro comprobaciones de firma solo las ejercitan los vectores unitarios (`test_dnssec.py` y compañía, con fixtures firmadas). Son ~380 líneas, el grueso de las 642; el día que el laboratorio sirva una zona firmada de verdad, bajan |
| Aritmética de curva en sus casos límite | `is_on_curve(None)`, escalar negativo | El punto del servidor pasa por el chequeo *on-curve* **antes** de la aritmética; el punto en el infinito y los escalares negativos no los produce nadie |
| Guardas que el propio llamante descarta | `_sha256_hex` con una huella que no empieza por `SHA256:` | El bucle que la llama ya salta las claves con error y sin huella, así que la huella siempre tiene esa forma. Lo mismo con `strength_for_modulus(None)` y `strength_level(None)` —los tres llamantes filtran antes—, con `assessment("kex")` —el bucle construye una valoración por **cada una** de las cinco clases— y con un certificado sin fechas: el objeto sólo se construye tras leerlas, **comprobado truncando el blob en cada frontera de campo** |
| Guardas que la selección previa descarta | `_kex_hash` con un método sin hash conocido, `_run_key_exchange` con uno sin implementar | `select_kex_for_probe` sólo devuelve nombres de las dos listas que el escáner sabe conducir, así que ninguno de los dos llega. Lo mismo con `parse_ext_info`/`parse_kexinit_payload` sobre el paquete equivocado —se llaman después de `read_message(TIPO)`—, con el `_mac` sin MAC —sólo las cifras AEAD no tienen, y ésas no pasan por ahí— y con `parse_host_key_blob` sin algoritmo: los dos llamantes pasan siempre uno |
| Detectores de defectos que no se pueden alimentar | `Ansi` con un estilo que no existe, una métrica declarada dos veces | Los nombres de estilo y las métricas son literales en el propio código, cada uno escrito una vez. Existen para que una errata en un renderizador falle en voz alta, y una errata no es una entrada |
| Guardas que el cargador de políticas descarta | `Policy.lookup` con una clase que no existe | El cargador **exige las cinco clases** (comprobado borrando una: rechaza el fichero). Igual con la escala de notas vacía, con las expectativas desconocidas y con el `return True` final de `check_expectation` |
| Contención de defectos | `except Exception` alrededor del parseo de la auditoría | Ninguna *entrada* llega: se le pasaron **4809 blobs malformados** a `parse_host_key_blob` —truncados en cada byte, con prefijos de longitud absurdos y al azar— y **ninguno** lanzó una excepción. Se prueba simulando el defecto, no alimentándolo |
| API para quien importe el paquete | `scan([])`, `analyse()` sobre un resultado fallido, `render()` con un formato inventado, `Tunnel.close()` sin haber abierto | La CLI rechaza el inventario vacío antes de llegar (comprobado ejecutándolo), `scan_target` vuelve antes de analizar cuando el estado no es OK, la CLI nombra los formatos y rechaza el que no conoce antes de renderizar, y `open_tunnel` sólo devuelve túneles abiertos. La tabla de resumen vacía es lo mismo visto desde el informe: sin objetivos no hay filas |
| Un `nameserver` a medias | Una línea `nameserver` sin dirección detrás | El fichero del resolvedor **sí** se controla ahora, desde el contenedor que ejecuta la herramienta: vacío y sin permisos de lectura son dos casos del laboratorio. Una línea `nameserver` truncada es la tercera forma y no la produce ningún resolvedor |
| Un fallo al escribir | `_send` con `OSError` | La escritura del cliente es de un kilobyte y ocurre **microsegundos** después de leer el banner: el reset del par todavía no ha llegado. Medido con seis construcciones —cierre con datos sin leer, `shutdown`, reset sin pausa, por el puerto publicado y contra la IP del contenedor— **0 de 20 en todas**. Es el fallo de una red que corta la conexión entre nuestra lectura y nuestra escritura, y el laboratorio no tiene red |
| La interfaz web en sus dos redes de contención | `except BaseException` alrededor del arranque del hilo de escaneo, y el descarte de conexión de `_BoundedServer` por encima de `MAX_CONNECTIONS` | El laboratorio conduce el asistente **entero** (100 % de `wizard.py`: responde los prompts contra un servidor del lab y lanza el escaneo, con todas las puertas de opciones, reprompts y cancelación) y la interfaz web casi entera (99 % de `web/server.py`: `POST /api/scan` contra el lab, cada formato descargado, más los brazos de validación, el token, el filtro de objetivos/DNS privados, el tope de tamaño, la concurrencia 503 y la expulsión del almacén). Lo que queda son dos redes de contención de recursos —agotar hilos/memoria al arrancar el escaneo, y superar 64 conexiones simultáneas— que sólo se alcanzan simulando el fallo, no alimentándolo; están en `test_web.py`. El `python -m ssh_crypto_checker.web` es la tercera: sólo corre como subproceso que se bloquea en `serve_forever`, y `server.main` ya se conduce directo |
| La interfaz MCP entera | `mcp/server.py`, `mcp/__init__.py`, `mcp/__main__.py` | El laboratorio escanea **servidores SSH**; no le habla JSON-RPC a un servidor MCP suyo, así que —al contrario que la web, que el laboratorio sí conduce vía su test— **ninguna** línea del MCP la alcanza el laboratorio. Es una tercera cara de la herramienta, como la web: la cubre por completo la suite unitaria (`tests/test_mcp.py`, 100 % de `mcp/`), que conduce el transporte JSON-RPC, cada método, cada herramienta y las tres salidas de `SystemExit`. Igual que `web/server.py`, entra en esta lista porque el laboratorio SSH no tiene con qué ejercitarla |

El primer grupo se queda: quitar la validación de argumentos de una primitiva
criptográfica para subir un número sería exactamente lo contrario de lo que
este proyecto pretende. Los demás admiten discusión —son guardas redundantes o
superficie sin usar, y borrarlas es tan legítimo como cubrirlas— y cada vez que
una se ha borrado ha sido con su motivo en el mensaje del commit, no en una
lista de exclusiones.

### Perseguir la cobertura encontró un fallo de verdad

Una regla que nombrara una clase de algoritmo inexistente —`cyphers` en vez de
`cipher`— lanzaba un `KeyError` pelado dentro del evaluador. Como `scan_target`
captura sus propios errores, el resultado era que **todos los servidores salían
como no escaneables**, y el motivo que se imprimía señalaba al servidor en vez
de al error de tecleo en la política. Un carácter mal puesto tumbaba la
ejecución entera y culpaba a quien no era.

Ahora se rechaza **al leer el fichero**, que es donde se cazan los demás errores
de ese fichero, y el mensaje nombra la clase inventada y lista las que existen.
Además `offered()` traduce cualquier `KeyError` a un `DetectionError`, como red
de seguridad: una regla rota debe costar su propio resultado y nada más.

Es el argumento a favor de medir. Ese camino tenía tests unitarios y pasaban
todos; lo que no tenía era a nadie ejecutándolo contra un servidor real.

## Ejecutar los tests

```bash
python3 -m unittest discover -s tests -t .     # todo
python3 -m unittest tests.test_analysis -v     # un módulo
python3 -m unittest tests.test_crypto.CurveTests.test_order_times_generator_is_the_point_at_infinity
```

No hacen falta dependencias ni red: `tests/fake_ssh_server.py` levanta un servidor
SSH mínimo en `127.0.0.1` que habla lo justo para ser escaneado, con listas de
algoritmos configurables.

Los tests de `tests/test_crypto.py` merecen una mención: las constantes de las
curvas y los primos no se comparan contra una copia de sí mismas —eso no
detectaría nada— sino contra sus propiedades matemáticas. Se verifica que el
generador está en la curva, que `n·G` es el punto del infinito y que los módulos
Diffie-Hellman son primos seguros. Una errata en cualquier dígito hace fallar el
test.

## Dónde vive cada cosa

| | |
|---|---|
| `analysis.py` | El **orquestador**: qué se ejecuta, en qué orden, y qué se hace con ello. No decide nada |
| `assessment.py` | El **modelo**: clasifica, mide fuerza, calcula nota y veredicto. **No es ampliable por plugins** |
| `plugins/__init__.py` | Qué **es** un plugin: metadatos, tipos de retorno, la vista que recibe |
| `plugins/runner.py` | Cómo la respuesta de un plugin se convierte en resultado |
| `plugins/builtin/` | Las comprobaciones, una por sujeto |
| `vulnerabilities.py` | El motor de las reglas declarativas del JSON |
| `data/algorithms.json` | Los algoritmos, las reglas y los umbrales |

`plugins/__init__.py` **no sabe** qué es un hallazgo ni un informe; `runner.py`
es el único que lo sabe. Esa separación es la que permite escribir un plugin
contra una superficie pequeña y estable mientras los tipos de resultado se
mueven por debajo.

## Añadir una comprobación

Una comprobación vive en uno de dos sitios, y elegir bien es la mitad del
trabajo. **Si se decide comparando algo que el servidor anuncia** —un nombre de
algoritmo, una ventana de versiones, el valor de una directiva— es una **regla
declarativa** en el fichero de política, sin código: los algoritmos y sus
etiquetas en [`politica-algoritmos.md`](politica-algoritmos.md), las
vulnerabilidades en [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md).
La gramática de detección incluye además las condiciones `auth_method` (un
método de autenticación ofrecido) y `extension` (una extensión RFC 8308
anunciada), las dos con `--auth-methods`.

**Si tiene que *calcular* algo** —dividir un número, restar dos fechas,
factorizar un módulo— es un **plugin**: ver [`plugins.md`](plugins.md), donde el
`KIND` distingue un `check` (un servidor), un `fleet` (todos a la vez) y una
`vulnerability` (un ataque publicado con identificador propio). Si dudas, prueba
primero con una regla: no ejecuta código, la puede editar quien no programa y no
puede romper un escaneo. Las dos formas se prueban contra el laboratorio.

## Las reglas de la casa

Cuatro cosas que el sistema garantiza, y que conviene no romper:

1. **Un plugin roto no rompe un escaneo.** Lo que lance se captura y se informa
   nombrando el plugin y la excepción.
2. **Ningún plugin cambia la nota.** Hay un test que escanea con todos los
   plugins y sin ninguno y exige que `score`, `grade` y `verdict` coincidan.
3. **No mirar no es no encontrar.** Si una comprobación no se pudo hacer, se
   dice; nunca se informa como «no afectado».
4. **`analysis.py` no tiene comprobaciones.** Hay un test que falla si alguien
   añade una. Van en un plugin o en el JSON.

## Añadir un formato de salida

Crear `reporting/mi_formato.py` con
`render(report, policy, options) -> str` y registrarlo en `FORMATS` y
`EXTENSIONS` de `reporting/__init__.py`. Los tests de contrato en
`tests/test_reporting.py` lo recogen automáticamente.

## Estilo

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy ssh_crypto_checker
```

Líneas de 100 columnas, anotaciones de tipo en todas las funciones públicas,
`from __future__ import annotations` en todos los módulos (compatibilidad con
Python 3.9).
