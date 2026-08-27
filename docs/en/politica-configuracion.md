# Policy manual — configuration checks

> Before this, read [`politicas.md`](politicas.md).

These checks look at **directives**, not algorithms: `PermitRootLogin`,
`MaxAuthTries`, `StrictHostKeyChecking`. There are two lists, with the same
grammar:

| List | Looks at | Requires |
|---|---|---|
| `sshd_config_checks` | The **server's** effective configuration, exactly as `sshd -T` resolves it. | `--audit-config` and credentials |
| `ssh_config_checks` | The effective configuration of this machine's **client**, according to `ssh -G`. | `--audit-client` |

> **What is checked is what the server resolved, not what the file says.** An
> `sshd_config` with a directive written twice, inside a `Match` block, or
> overridden by an included file, does not say what it seems to say.
> `sshd -T` says what is actually going to happen.

---

## The authenticated audit: what it inspects

Everything visible from the network falls short: **most real misconfigurations do
not show up in a KEXINIT.** `--audit-config` enters the server with the
inventory's credentials (`user=`, `auth=`, `key=`, `password-env=`) and reads its
effective configuration. The account needs to be root or have **passwordless sudo
for `sshd`**:

```
# /etc/sudoers.d/auditoria
auditor ALL=(root) NOPASSWD: /usr/sbin/sshd
```

**Two design decisions:**

- **It reads `sshd -T`, not the file.** `sshd -T` prints what sshd actually
  resolved: it follows the `Include`s, applies the defaults and normalizes.
  Reading `/etc/ssh/sshd_config` directly gives a self-assured and sometimes wrong
  answer, because since OpenSSH 8.2 the configuration is spread across
  `sshd_config.d` and because an unset directive **still has a default value that
  matters**.
- **It delegates the connection to the system's `ssh` client.** Implementing
  authenticated SSH here would mean signing with Ed25519 and RSA, reading OpenSSH
  private keys and decrypting them with `bcrypt-pbkdf`: a great deal of
  cryptographic code to reimplement something already on any machine that runs
  this, and which already integrates with the agent, `~/.ssh/config` and
  `known_hosts`. The password, if any, is passed via `SSH_ASKPASS` with the secret
  in an environment variable; **it is never written to disk**.

Beyond the sixteen directives of `sshd_config_checks` (`PermitRootLogin`,
`PasswordAuthentication`, `PermitEmptyPasswords`, `StrictModes`, `MaxAuthTries`,
the forwardings…), the authenticated audit looks at what no directive captures:

- **Permissions and owner** of the host private keys, the `sshd_config` and the
  `authorized_keys`, resolving the paths from the `HostKey` directives themselves
  rather than assuming `/etc/ssh`.
- **The audited account's `authorized_keys`**, entry by entry: unrestricted
  options (`restrict`, `from=`, `command=`), obsolete types (`ssh-dss`,
  `ssh-rsa`), **keys below the policy's minimum size** —the same one required of
  host keys, because the arithmetic does not care which end of the connection the
  key is on—, **expired** entries still in the file and entries with **no expiry**.
  The last are the important case: access that must be revoked by hand tends not
  to be, and a key issued to someone long gone keeps working until someone deletes
  the line. A `cert-authority` entry is not counted, because there validity lives
  in the certificates the CA issues. Key material is not copied to the report: the
  fingerprint is enough.
- ***Every* account's `authorized_keys`**, not just the audited one. `getent
  passwd` is walked and each login-capable account's file is read. This is where
  access accumulates: the audited account is the one someone is looking after, and
  the other forty are the ones nobody has opened since 2019. Reading another
  user's file requires root, so **each account is reported as read or not read** —
  one that could not be checked is not counted as clean. If `AuthorizedKeysFile`
  has no `%u`, all accounts share one file and that is warned separately.
- **User private keys** (`~/.ssh/id_*`): type, size, permissions and whether they
  have a passphrase. A key with no passphrase is a credential in a file, and no
  server setting changes that.
- **`/etc/ssh/moduli`**: the Diffie-Hellman group measured in a scan is only the
  one the server chose *for this client*. The file says what else it has
  available, which is what a less careful client would negotiate.
- **The distribution package**: the package version settles the by-version
  finding's warning —`1:8.4p1-5+deb11u7` is a patched 8.4p1— and the report gives
  the exact command to read its changelog.
- **`Match` blocks, resolved and not just flagged.** `sshd -T` without context
  shows the global configuration, so a `Match` that relaxes something for a group
  is invisible in it. The tool builds a connection context from each block's
  criteria (`User`, `Group` —resolved to a member—, `Address`, `Host`,
  `LocalPort`), asks `sshd -T -C` again and compares. It reports only what gets
  **worse**. What cannot be represented with a single context —negated criteria
  like `Match User *,!nobody`— is returned **with its reason** for manual review; a
  block that was not resolved is never confused with a harmless one. The finding
  names **the affected connection, not the culprit block**: sshd applies every
  matching block.
- **Which CVE the package says it fixed.** The installed package's changelog is
  read —local, no network— and the CVEs it mentions are extracted: a CVE named in
  it was addressed in that revision or earlier, which is what "the distribution
  backported the patch" means. A by-version finding the changelog mentions is
  recorded as **informational**, with the reason and the changelog path, so that
  `--fail-on high` does not fail a CI over a fully patched Debian; the
  vulnerability record keeps its original severity. **It is never applied to what
  is observed on the wire**: a changelog cannot un-offer a CBC cipher, and that
  safeguard has its own test.

---

## The shape of a check

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

| Field | Required | Notes |
|---|---|---|
| `id` | **yes** | Unique across all checks. |
| `directive` | **yes** | **In lowercase**, which is how `sshd -T` prints them. |
| `expect` | **yes** | The expectation. If it is **not** met, there is a finding. |
| `severity` | **yes** | `critical` … `info`. |
| `title`, `description`, `remediation` | yes in practice | What gets read. |

**`expect` describes what should be, not what is wrong.** The finding is
produced when reality does not match the expectation. Writing it the other way
around is the most frequent mistake, and it produces checks that fire on
well-configured servers.

---

## The six expectations

| Expectation | Met when | Example |
|---|---|---|
| `equals` | The value is exactly that one. | `{"equals": "no"}` |
| `in` | The value is in the list. | `{"in": ["no", "ask"]}` |
| `not_in` | The value is **not** in the list. | `{"not_in": ["yes"]}` |
| `at_most` | The number is less than or equal. | `{"at_most": 4}` |
| `at_least` | The number is greater than or equal. | `{"at_least": 2}` |
| `required` | The directive is present (`true`) or absent (`false`). | `{"required": true}` |

Text comparisons are case-insensitive. `at_most` and `at_least` on something
that is not a number are simply not met, instead of blowing up.

**A directive that `sshd -T` does not print has no value**, and that can only
satisfy `{"required": false}`. For everything else, there is no value to
compare, and the check cannot be met: the tool does not invent a default value
it has not seen.

---

## Adding a check, step by step

1. **Find out what the directive is really called.** On a server:

```bash
sudo sshd -T | sort | grep -i clientalive
```

`sshd -T` prints **in lowercase** and without the camel-case name: it is
`clientaliveinterval`, not `ClientAliveInterval`. A misspelled name produces a
check that is never met or one that never fires, depending on the
expectation — and neither of the two warns you.

2. **Write the expectation as the good state.**

3. **Write the remediation with the exact line** to put in. Whoever reads the
report wants to copy it.

4. **Test it against the lab**, which has an auditable server with
credentials:

```bash
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2214 \
    --audit-config --user audit -i lab/lab-audit-key --no-color
```

5. **Check both sides**: that it fires on the misconfigured server and that it
does **not** fire on the well-configured one.

---

## Example: agent forwarding

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

## What these checks do **not** do

- **They do not read files.** The permissions of `/etc/ssh/ssh_host_*`, the
  contents of `moduli` or the `authorized_keys` are not directives: the
  `server_files` plugin and friends look at those.
- **They do not score by themselves.** They produce findings with their
  severity; the grade is computed by the scoring part. See
  [`politica-puntuacion.md`](politica-puntuacion.md).
- **They do not work without credentials.** Without `--audit-config` there is
  no configuration to look at, and the report says it was not assessed instead
  of staying silent.
