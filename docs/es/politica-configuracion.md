# Manual de política — comprobaciones de configuración

> Antes de esto, lee [`politicas.md`](politicas.md).

Estas comprobaciones miran **directivas**, no algoritmos: `PermitRootLogin`,
`MaxAuthTries`, `StrictHostKeyChecking`. Hay dos listas, con la misma
gramática:

| Lista | Mira | Hace falta |
|---|---|---|
| `sshd_config_checks` | La configuración efectiva del **servidor**, tal y como `sshd -T` la resuelve. | `--audit-config` y credenciales |
| `ssh_config_checks` | La configuración efectiva del **cliente** de esta máquina, según `ssh -G`. | `--audit-client` |

> **Se mira lo que el servidor resolvió, no lo que pone en el fichero.** Un
> `sshd_config` con una directiva escrita dos veces, dentro de un bloque
> `Match`, o sobrescrita por un fichero incluido, no dice lo que parece decir.
> `sshd -T` dice lo que de verdad va a pasar.

---

## La auditoría autenticada: qué inspecciona

Todo lo que se ve desde la red se queda corto: **la mayoría de las malas
configuraciones reales no se ven en un KEXINIT.** `--audit-config` entra en el
servidor con las credenciales del inventario (`user=`, `auth=`, `key=`,
`password-env=`) y lee su configuración efectiva. La cuenta necesita ser root o
tener **sudo sin contraseña para `sshd`**:

```
# /etc/sudoers.d/auditoria
auditor ALL=(root) NOPASSWD: /usr/sbin/sshd
```

**Dos decisiones de diseño:**

- **Lee `sshd -T`, no el fichero.** `sshd -T` imprime lo que sshd realmente
  resolvió: sigue los `Include`, aplica los valores por defecto y normaliza. Leer
  `/etc/ssh/sshd_config` directamente da una respuesta segura de sí misma y a
  veces equivocada, porque desde OpenSSH 8.2 la configuración se reparte en
  `sshd_config.d` y porque una directiva sin poner **sigue teniendo un valor por
  defecto que importa**.
- **Delega la conexión en el cliente `ssh` del sistema.** Implementar SSH
  autenticado aquí significaría firmar con Ed25519 y RSA, leer claves privadas en
  formato OpenSSH y descifrarlas con `bcrypt-pbkdf`: muchísimo código
  criptográfico para reimplementar algo que ya está en cualquier máquina que
  ejecute esto, y que además ya se integra con el agente, `~/.ssh/config` y
  `known_hosts`. La contraseña, si la hay, se pasa por `SSH_ASKPASS` con el
  secreto en una variable de entorno; **nunca se escribe en disco**.

Más allá de las dieciséis directivas de `sshd_config_checks`
(`PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`,
`StrictModes`, `MaxAuthTries`, los reenvíos…), la auditoría autenticada mira lo
que ninguna directiva captura:

- **Permisos y propietario** de las claves privadas de host, del `sshd_config` y
  del `authorized_keys`, resolviendo las rutas desde las propias directivas
  `HostKey` en vez de suponer `/etc/ssh`.
- **`authorized_keys` de la cuenta auditada**, entrada por entrada: opciones sin
  restricción (`restrict`, `from=`, `command=`), tipos obsoletos (`ssh-dss`,
  `ssh-rsa`), **claves por debajo del tamaño mínimo** de la política —el mismo
  que se exige a las claves de host, porque la aritmética no distingue en qué
  extremo de la conexión está la clave—, entradas **caducadas** que siguen en el
  fichero y entradas **sin caducidad**. Estas últimas son el caso importante: el
  acceso que hay que revocar a mano tiende a no revocarse, y una clave emitida a
  alguien que ya se fue sigue funcionando hasta que alguien borra la línea. Una
  entrada `cert-authority` no se cuenta, porque ahí la vigencia está en los
  certificados que emite la CA. El material de clave no se copia al informe:
  basta la huella.
- **`authorized_keys` de *todas* las cuentas**, no solo la auditada. Se recorre
  `getent passwd` y se lee el fichero de cada cuenta que pueda iniciar sesión.
  Aquí es donde se acumula el acceso: la cuenta auditada es la que alguien está
  cuidando, y las otras cuarenta son las que nadie ha abierto desde 2019. Leer el
  fichero de otro usuario requiere root, así que **cada cuenta se reporta como
  leída o no leída** — una que no se pudo comprobar no se cuenta como limpia. Si
  `AuthorizedKeysFile` no lleva `%u`, todas las cuentas comparten un mismo fichero
  y eso se avisa aparte.
- **Claves privadas de usuario** (`~/.ssh/id_*`): tipo, tamaño, permisos y si
  tienen passphrase. Una clave sin passphrase es una credencial en un fichero, y
  ningún ajuste del servidor cambia eso.
- **`/etc/ssh/moduli`**: el grupo Diffie-Hellman que se mide en un escaneo es solo
  el que el servidor eligió *para este cliente*. El fichero dice qué más tiene
  disponible, que es lo que negociaría un cliente menos cuidadoso.
- **El paquete de la distribución**: la versión del paquete zanja la advertencia
  de los hallazgos por versión —`1:8.4p1-5+deb11u7` es un 8.4p1 parcheado— y el
  informe da el comando exacto para consultar su changelog.
- **Bloques `Match`, resueltos y no solo señalados.** `sshd -T` sin contexto
  muestra la configuración global, así que un `Match` que relaja algo para un
  grupo es invisible en ella. La herramienta construye un contexto de conexión a
  partir de los criterios de cada bloque (`User`, `Group` —resuelto a un miembro—,
  `Address`, `Host`, `LocalPort`), vuelve a pedir `sshd -T -C` y compara. Solo
  informa de lo que **empeora**. Lo que no se puede representar con un solo
  contexto —criterios negados como `Match User *,!nobody`— se devuelve **con su
  motivo** para revisarlo a mano; un bloque que no se resolvió no se confunde
  nunca con uno inocuo. El hallazgo nombra **la conexión afectada, no el bloque
  culpable**: sshd aplica todos los bloques que coinciden.
- **Qué CVE dice el paquete que ha corregido.** Se lee el changelog del paquete
  instalado —local, sin red— y se extraen los CVE que menciona: un CVE nombrado en
  él se atendió en esa revisión o antes, que es lo que significa «la distribución
  retroportó el parche». Un hallazgo por versión que el changelog menciona se
  registra como **informativo**, con el motivo y la ruta del changelog, para que
  `--fail-on high` no tumbe una CI por un Debian íntegramente parcheado; el
  registro de la vulnerabilidad conserva la severidad original. **Nunca se aplica
  a lo observado en la conexión**: un changelog no puede des-ofrecer un cifrado
  CBC, y esa salvaguarda tiene su propio test.

---

## La forma de una comprobación

```json
{
  "id": "permit-root-login",
  "directive": "permitrootlogin",
  "severity": "high",
  "expect": { "in": ["no", "prohibit-password", "forced-commands-only"] },
  "title": "Se puede entrar directamente como root",
  "description": "Entrar como root borra el rastro de quién hizo qué y convierte la cuenta más valiosa en la que reciben los ataques de fuerza bruta.",
  "remediation": "Pon 'PermitRootLogin no', o 'prohibit-password' si de verdad hace falta."
}
```

| Campo | Obligatorio | Notas |
|---|---|---|
| `id` | **sí** | Único entre todas las comprobaciones. |
| `directive` | **sí** | **En minúsculas**, que es como `sshd -T` las imprime. |
| `expect` | **sí** | La expectativa. Si **no** se cumple, hay hallazgo. |
| `severity` | **sí** | `critical` … `info`. |
| `title`, `description`, `remediation` | sí en la práctica | Lo que se lee. |

**`expect` describe lo que debería ser, no lo que está mal.** El hallazgo se
produce cuando la realidad no encaja con la expectativa. Escribirlo al revés
es el error más frecuente y produce comprobaciones que saltan en los
servidores bien configurados.

---

## Las seis expectativas

| Expectativa | Se cumple cuando | Ejemplo |
|---|---|---|
| `equals` | El valor es exactamente ese. | `{"equals": "no"}` |
| `in` | El valor está en la lista. | `{"in": ["no", "ask"]}` |
| `not_in` | El valor **no** está en la lista. | `{"not_in": ["yes"]}` |
| `at_most` | El número es menor o igual. | `{"at_most": 4}` |
| `at_least` | El número es mayor o igual. | `{"at_least": 2}` |
| `required` | La directiva está presente (`true`) o ausente (`false`). | `{"required": true}` |

Las comparaciones de texto no distinguen mayúsculas. `at_most` y `at_least`
sobre algo que no es un número no se cumplen, en vez de reventar.

**Una directiva que `sshd -T` no imprime no tiene valor**, y eso solo puede
satisfacer a `{"required": false}`. Para todo lo demás, no hay valor que
comparar, y la comprobación no puede cumplirse: la herramienta no inventa un
valor por defecto que no ha visto.

---

## Añadir una comprobación, paso a paso

1. **Mira cómo se llama de verdad la directiva.** En un servidor:

```bash
sudo sshd -T | sort | grep -i clientalive
```

`sshd -T` imprime **en minúsculas** y sin el nombre en camello: es
`clientaliveinterval`, no `ClientAliveInterval`. Un nombre mal escrito produce
una comprobación que no se cumple nunca o que no salta nunca, según la
expectativa — y ninguna de las dos avisa.

2. **Escribe la expectativa como el estado bueno.**

3. **Escribe la remediación con la línea exacta** que hay que poner. Quien lea
el informe quiere copiarla.

4. **Pruébala contra el laboratorio**, que tiene un servidor auditable con
credenciales:

```bash
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2214 \
    --audit-config --user audit -i lab/lab-audit-key --no-color
```

5. **Comprueba los dos lados**: que salta en el servidor mal configurado y que
**no** salta en el bien configurado.

---

## Ejemplo: reenvío de agente

```json
{
  "id": "agent-forwarding-allowed",
  "directive": "allowagentforwarding",
  "severity": "low",
  "expect": { "equals": "no" },
  "title": "El reenvío de agente está permitido",
  "description": "Con el agente reenviado, quien tenga root en este servidor puede usar la clave del usuario para saltar a cualquier otro sitio donde esa clave valga, mientras la sesión esté abierta.",
  "remediation": "Pon 'AllowAgentForwarding no'. Si alguien necesita saltar desde aquí, usa ProxyJump, que no expone la clave."
}
```

---

## Lo que estas comprobaciones **no** hacen

- **No leen ficheros.** Los permisos de `/etc/ssh/ssh_host_*`, el contenido de
  `moduli` o las `authorized_keys` no son directivas: los mira el plugin
  `server_files` y compañía.
- **No puntúan por sí mismas.** Producen hallazgos con su severidad; la nota
  la calcula la parte de puntuación. Ver
  [`politica-puntuacion.md`](politica-puntuacion.md).
- **No funcionan sin credenciales.** Sin `--audit-config` no hay
  configuración que mirar, y el informe dice que no se evaluó en vez de callar.
