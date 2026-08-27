# Manual de uso avanzado

> Volver al [`README.md`](README.md). Cada opción tiene además su ejemplo en el «Recetario» del README.

## Comparar con un escaneo anterior

Un informe dice cómo está un servidor hoy. Lo que normalmente hace falta saber
es **qué ha cambiado**: qué apareció desde la última auditoría, qué se arregló y
qué empeoró en silencio tras una actualización de paquetes que nadie anunció.

`--compare` toma un informe JSON anterior como línea base:

```bash
# Guardar la línea base
ssh-crypto-checker -f inventario.txt --format json -o base.json

# ... semanas después ...
ssh-crypto-checker -f inventario.txt --compare base.json
```

```
Changes since the baseline
base.json, scanned 2026-07-01T09:12:44+00:00

127.0.0.1:2201: regressed, grade A+ -> C
127.0.0.1:2201: NEW [medium] Weak encryption algorithm(s) offered
127.0.0.1:2201: NEW [medium] CVE-2008-5161: CBC plaintext recovery
127.0.0.1:2201: now offers cipher: aes128-cbc
127.0.0.1:2201: no longer offers cipher: aes256-ctr
```

Se informa de:

- **Hallazgos nuevos y resueltos**, por identificador, no por texto.
- **Movimiento de nota**, indicando si mejoró o empeoró.
- **Algoritmos añadidos y retirados**, por clase.
- **Cambios de clave de host**, que en un servidor que no se ha reinstalado son
  motivo para parar y averiguar por qué.
- **Servidores nuevos** y **servidores que estaban en la base y ya no aparecen**.

La comparación se hace sobre el JSON, así que la línea base puede ser un
artefacto guardado de una ejecución anterior de CI; la herramienta no necesita
almacenar nada.

### Histórico: la serie, no solo el salto

`--compare` responde a «qué ha cambiado desde ese informe». Lo que no puede
responder es «desde cuándo pasa esto», porque un fichero de línea base es un
solo punto. `--history` acumula cada escaneo en un fichero, una línea por
ejecución:

```bash
ssh-crypto-checker -f inventario.txt --history historico.jsonl --history-report
```

```
Scanned                     Hosts    Avg  Vuln  Crit  High
2026-06-01T03:00:11+00:00  26/27     71.4    18     3    11
2026-07-01T03:00:09+00:00  26/27     74.2    16     1     9
2026-08-01T03:00:14+00:00  27/27     79.8    12     0     6
```

Cada línea es un informe completo, así que **`--compare` acepta el mismo
fichero** y usa su entrada más reciente: mantener una serie no obliga a
mantener además una línea base aparte.

```bash
ssh-crypto-checker -f inventario.txt --history historico.jsonl \
    --compare historico.jsonl --fail-on-regression
```

Es JSON Lines y no un array, porque añadir a un array obliga a reescribir el
fichero, y un escaneo interrumpido a mitad de esa reescritura deja **sin
histórico**. Una línea corrupta se salta: un fichero escrito durante meses no
puede volverse ilegible entero por una escritura truncada.

Con `--fail-on-regression` el proceso termina con código 1 si algún servidor
empeoró, aunque su estado absoluto siga estando por encima de `--fail-on`. Es la
diferencia entre "esto no cumple" y "esto ha empeorado", y en un parque grande
la segunda es la que se detecta a tiempo:

```yaml
auditoria-ssh:
  script:
    - ssh-crypto-checker -f inventario.txt --format json -o informe.json
                         --compare base.json --fail-on-regression
```

---

## Auditar el cliente

Todo lo demás en esta herramienta juzga al servidor. Pero un cliente permisivo
deshace buena parte del trabajo: la clave de host más fuerte del mundo, en el
servidor mejor configurado, **no se comprueba en absoluto** si al cliente se le
dijo que acepte cualquiera.

```bash
ssh-crypto-checker servidor.example.com --audit-client
```

`ssh -G` es al cliente lo que `sshd -T` al servidor: resuelve el fichero del
sistema, el del usuario, cada bloque `Host` y `Match` y los valores compilados
por defecto, e imprime lo que esa conexión usaría de verdad. Se pregunta por un
destino concreto **a propósito**: un bloque `Host` puede relajar los ajustes
para un objetivo sin que nada global lo delate. No abre ninguna conexión.

| Comprobación | Por qué importa |
|---|---|
| `StrictHostKeyChecking no` | **Crítico.** Se conecta a lo que responda. Es toda la defensa contra un atacante en el camino |
| `UserKnownHostsFile /dev/null` | **Crítico.** Toda conexión es la primera, así que un cambio de clave nunca se puede notar |
| `ForwardAgent yes` | Quien tenga root en el servidor destino puede autenticarse como tú en todas partes |
| `ForwardX11Trusted yes` | El host remoto puede leer pulsaciones destinadas a otras ventanas. Es el valor por defecto en Debian |
| `IdentitiesOnly no` | Ofreces cada clave a cada servidor: un mapa de dónde tienes acceso |
| `HashKnownHosts no` | `known_hosts` en claro es la lista de a dónde ir después desde una máquina comprometida |
| `PermitLocalCommand yes` | Ejecución de código local si alguien más puede escribir tu configuración |
| `CheckHostIP no` | No se avisa cuando un nombre conocido empieza a resolver a otro sitio |
| `VerifyHostKeyDNS yes` | Es la precondición de `CVE-2025-26465`; solo es sensato con DNSSEC validado |

Además, **los algoritmos del propio cliente** se clasifican con la misma
política que los del servidor. La negociación elige algo que ambos extremos
aceptan, así que un cliente que aún ofrece `3des-cbc` lo usará contra cualquier
servidor que lo permita — endurecer los servidores no lo quita, endurecer el
cliente sí.

Las comprobaciones son **datos**, igual que las de `sshd_config`: viven en
`ssh_config_checks` dentro de `algorithms.json` y usan el mismo esquema
`expect`.

---

## Escanear tras un bastión

Una red segmentada obliga a saltar por un host intermedio. `ProxyJump` no
sirve aquí: esa opción es del cliente ssh, y en el camino del escaneo **no hay
cliente ssh** — la herramienta abre sus propios sockets, que es justo lo que le
permite ver lo que un servidor ofrece sin autenticarse.

Así que el salto se hace al revés. Con `-J` se abre un reenvío de puerto local
a través del bastión y el escaneo se conecta al extremo local:

```bash
ssh-crypto-checker -f inventario.txt -J bastion.example.com
```

El informe **sigue nombrando el objetivo real**: `127.0.0.1:41337` no le sirve
a nadie. Se añade además por dónde se llegó.

El bastión es un destino ssh, así que lo normal es tenerlo en `~/.ssh/config`.
Si no, admite `[usuario@]host[:puerto]`, y `--jump-option` pasa opciones
sueltas a esa conexión (con la forma `=`, porque el valor empieza por guion):

```bash
ssh-crypto-checker servidor.interno -J ops@bastion:2222 \
    --jump-option=-oIdentityFile=~/.ssh/bastion
```

Tres decisiones que conviene conocer:

- **`--max-startups` se omite tras un bastión.** La sonda cuenta cuántas
  conexiones sin autenticar aguanta el servidor, y cada una sería además un
  canal de la sesión del bastión: lo que volvería es el menor de los dos
  límites, presentado como si fuera el del objetivo. Un número equivocado es
  peor que ningún número.
- **La auditoría autenticada reutiliza el mismo reenvío**, no hace un salto
  propio. `ssh -J` no vale para eso: ssh construye el comando interno él mismo
  y casi ninguna de nuestras opciones llega hasta él, así que la clave de host
  del bastión no se podría tratar como el usuario pidió.
- **La clave del objetivo se registra con `HostKeyAlias`**, bajo su nombre
  real. Sin eso, `known_hosts` se llenaría de entradas de puertos efímeros y la
  clave del servidor no se contrastaría nunca contra nada.

> El túnel **no debilita** la comprobación de la clave del bastión. Usa la
> configuración ssh de quien ejecuta; en una herramienta que audita seguridad
> SSH, saltarse eso por comodidad sería difícil de defender.

---

## Fichero de servidores y credenciales

Un objetivo por línea. `#` inicia un comentario. Lo que siga al primer token
separado por espacios se usa como **etiqueta** en el informe (hay un inventario
de ejemplo listo para copiar en [`examples/`](../../examples/README.md)):

```
# Inventario de producción
web01.example.com:22        frontend web
web02.example.com:22        frontend web
192.0.2.10                  base de datos
[2001:db8::1]:2222          router de borde
bastion.example.com         # solo comentario, sin etiqueta
```

```bash
ssh-crypto-checker -f inventario.txt
```

Se puede leer de la entrada estándar con `-f -`:

```bash
grep -h '^Host ' ~/.ssh/config | awk '{print $2}' | ssh-crypto-checker -f -
```

Los duplicados (mismo host y puerto) se eliminan. Una línea mal formada no
aborta el fichero: se avisa por `stderr` y se continúa.

### Cuántos servidores caben: lo medido, no lo estimado

Medido en esta máquina, no calculado a ojo. La primera tabla apunta a puertos
cerrados, así que es el coste del propio armazón sin red de por medio:

| Objetivos | Tiempo | Memoria máxima | Informe JSON |
|---|---|---|---|
| 200 | 0,9 s | 29 MB | 286 KiB |
| 1 000 | 1,8 s | 36 MB | 1,4 MiB |
| 5 000 | 6,0 s | 72 MB | 7,1 MiB |

Lineal en las dos cosas: unos **27 MB de base y ~9 KB por objetivo**
inalcanzable. Nada crece de forma rara, y nada se queda por el camino.

La segunda es un escaneo **real** de los 96 servidores del laboratorio, con
saludo SSH, clave de host y todas las sondas:

| `-c` | Tiempo | CPU |
|---|---|---|
| 1 | 37,9 s | 10 % |
| 4 | 19,5 s | 25 % |
| 8 | 18,7 s | — |
| 16 | 17,9 s | 31 % |
| 32 | 17,5 s | — |

Y aquí está lo que importa, porque no es lo que la gente supone: **pasar de 8 a
32 no arregla nada**. La CPU se queda en el 31 %, así que no es que la máquina
no dé más. El suelo lo pone **un solo objetivo**: el servidor del laboratorio
que acepta la conexión y no dice nada nunca cuesta 16,1 s con `-t 8`, porque
agota el tiempo de espera dos veces seguidas. Mientras ese siga ahí, el
escaneo no puede acabar antes.

> **La palanca es `-t`, no `-c`.** Subir la concurrencia reparte el trabajo;
> solo bajar el tiempo de espera baja el suelo. Con `-t 3` ese mismo servidor
> cuesta 6 s en vez de 16, y un escaneo grande termina antes — a cambio de
> arriesgarse a marcar como inalcanzable un servidor lento de verdad.

Un objetivo **real y completo** ocupa unos 48 KiB en el JSON y unos 155 KB en
memoria mientras dura el escaneo, porque el informe entero se construye en
memoria antes de escribirse. De ahí sale el techo práctico: **unos 5 000
servidores reales por ejecución rondan el gigabyte**. Para un parque mayor,
partir el inventario y escanear por lotes; no hay salida en *streaming*.

### Opciones por servidor

Tras el objetivo se pueden poner pares `clave=valor`. Lo que no sea una opción
reconocida se acumula como etiqueta, de modo que el formato antiguo sigue
funcionando:

```
# Inventario con credenciales
web01.example.com:22   user=admin auth=key key=~/.ssh/id_ed25519   frontend web
db01.example.com       user=svc auth=password password-env=DB01_PW
router.example.com     auth=none   router de borde
alt.example.com        port=2222 label=nodo alterno
192.0.2.10             servidor heredado
```

| Opción | Significado |
|---|---|
| `user=` / `username=` | Cuenta con la que autenticarse |
| `auth=` | `none` (anónimo), `key`, `password` o `any` (por defecto) |
| `key=` / `identity=` | Fichero de clave privada |
| `password-file=` | Fichero del que leer la contraseña (primera línea) |
| `password-env=` | Variable de entorno de la que leerla |
| `port=` | Puerto, alternativa a `host:puerto` |
| `label=` | Etiqueta explícita |

Los mismos valores se pueden dar como **parámetros del script**, y actúan de
defecto para los objetivos que no los definan:

```bash
ssh-crypto-checker -f inventario.txt --user auditor --auth key -i ~/.ssh/id_ed25519
ssh-crypto-checker -f inventario.txt --auth password --password-env SSH_PW
```

> 🔐 **No se admite una contraseña literal en el inventario.** Solo
> `password-file=` y `password-env=`, para que el fichero se pueda versionar sin
> filtrar un secreto. La contraseña se lee **en el momento de usarla**, nunca se
> guarda en el objeto del resultado, y cualquier campo cuyo nombre sugiera un
> secreto se sustituye por `[redacted]` al serializar el informe.

---

## Comprobaciones remotas adicionales

Además de los algoritmos, hay cosas que se pueden verificar **sin credenciales**.
Están desactivadas por defecto porque son más intrusivas o más lentas:

```bash
ssh-crypto-checker servidor.example.com --auth-methods --sshfp --login-grace
ssh-crypto-checker -f inventario.txt --all-checks      # las tres de golpe
```

### `--auth-methods` — métodos de autenticación aceptados

Lo más valioso que se puede saber sin entrar. La lista viaja en
`SSH_MSG_USERAUTH_FAILURE`, que el servidor solo manda **después** de cifrar la
sesión, así que la herramienta completa un intercambio de claves real (X25519,
las tres curvas NIST o *group exchange*), deriva las claves de sesión y cifra —
todo en Python puro, sin dependencias. Luego pide autenticarse con el método
`none`, que está diseñado para ser rechazado y devolver la lista.

Soporta los cuatro modos que usa SSH, así que **funciona contra cualquier
servidor**, desde uno moderno que solo ofrezca AEAD hasta uno antiguo que solo
ofrezca CBC:

| Modo | Verificado contra |
|---|---|
| AES-CTR | NIST SP 800-38A F.5.1 |
| AES-CBC | FIPS 197 (cifrado inverso) |
| AES-GCM | NIST GCM Test Case 3 y 4 |
| ChaCha20-Poly1305 | RFC 8439 §2.5.2 y el vector original de ChaCha20 |

MAC en ambos órdenes (clásico y *encrypt-then-MAC*), incluidos `hmac-sha1` y
`hmac-md5` como último recurso: usar un MAC roto para un paquete desechable no
es una decisión de seguridad, es la diferencia entre poder auditar un servidor
antiguo o no.

Detecta lo que ninguna lista de cifrados protege:

- **`password` o `keyboard-interactive` habilitados** → exposición a fuerza
  bruta, que es la vía de entrada más común a un SSH.
- **`none` aceptado** → el servidor da sesión a cualquiera. Hallazgo crítico.
- **`hostbased`** → se confía en la máquina cliente, no en el usuario.

> ⚠️ A diferencia del resto del escaneo, esto **deja una entrada de autenticación
> fallida en el log** del servidor y podría disparar un `fail2ban` si se repite.
> Por eso es opt-in. Con `user=` en el inventario se sondea la cuenta real, ya
> que los métodos pueden variar por usuario.

### `--sshfp` — huellas publicadas en DNS

Comprueba si existen registros SSHFP (RFC 4255) y si **cuadran con las claves
que el servidor presenta de verdad**. Sin ellos, un cliente que conecta por
primera vez no tiene con qué verificar la clave. Detecta también registros
obsoletos tras una rotación, y avisa si el resolutor no marcó la respuesta como
validada por DNSSEC (sin firmar, los registros los puede falsificar quien
controle el camino DNS). Cliente DNS propio, sin dependencias.

Con `--dns-server ADDR` se consulta un servidor de nombres concreto en vez de
los de `/etc/resolv.conf`, admitiendo `direccion`, `direccion:puerto` y
`[::1]:puerto`. Sirve cuando los registros viven en una zona interna que la
máquina desde la que escaneas no usa por defecto, o para comprobar un servidor
autoritativo antes de publicar. Se puede repetir.

```bash
ssh-crypto-checker servidor.interno --sshfp --dns-server 10.0.0.53
```

### `--login-grace` — `LoginGraceTime` observado

Mide cuánto aguanta el servidor una conexión sin autenticar. Importa porque el
paliativo documentado para regreSSHion (CVE-2024-6387) es ponerlo a 0, lo que
elimina el temporizador y cambia la vulnerabilidad por una exposición a
denegación de servicio. La espera es ociosa, así que con varios servidores en
paralelo cuesta casi lo mismo que con uno.

### `--known-hosts` — contraste con el registro local

Compara las claves con las de un fichero `known_hosts`, entendiendo tanto las
entradas en claro como las **con hash** (`HashKnownHosts`, el valor por defecto
en muchos sistemas, donde el nombre se guarda como HMAC-SHA1 con sal). Detecta
que una clave **ha cambiado** respecto a lo registrado —rotación no documentada
o interceptación— y claves marcadas `@revoked` que siguen en servicio.

### `--max-startups` — huecos de preautenticación

Abre conexiones concurrentes sin autenticar hasta que el servidor deja de
aceptarlas. Esos huecos son lo que un atacante agota para dejar fuera a los
usuarios reales, y un `LoginGraceTime` largo hace que cada uno sea más barato de
mantener. **Es una pequeña denegación de servicio deliberada contra el objetivo**,
así que está fuera de `--all-checks` y tiene límite.

### `server-sig-algs` (RFC 8308, automático con `--auth-methods`)

Los algoritmos de firma que el servidor acepta **de los clientes**. Esto no se
ve en el KEXINIT: un servidor puede presentar una clave de host fuerte y a la
vez seguir aceptando firmas SHA-1 de sus usuarios. Se obtiene del
`SSH_MSG_EXT_INFO` que el servidor manda tras cifrar la sesión.

### Algoritmo preferido (automático)

El **primero** de cada lista es lo que negocia un cliente permisivo, así que el
orden importa tanto como la pertenencia. Si el primero es débil o inseguro se
emite un hallazgo, aunque más abajo haya algoritmos excelentes que nunca se
usarán.

### Claves de host compartidas (automático)

No necesita opción: al escanear varios servidores, la herramienta compara las
huellas y **avisa si dos comparten clave de host**. Casi siempre son máquinas
clonadas o una imagen con la clave dentro, y significa que quien extraiga la
privada de una puede suplantar a todas. Solo es visible mirando el parque
entero, así que se decide al terminar el escaneo.
