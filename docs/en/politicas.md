# Policy file manual — overview

The policy file is **the tool's judgment written as data**.
Which algorithm is good, which vulnerability exists, how much each thing weighs
in the grade, what each standard requires: all of that is edited without
touching Python.

The reason is practical. What is secure today may not be tomorrow, and updating
the tool must mean **editing a JSON file**, not deploying a new release.
Someone has to be able to change the criteria on a bastion host, at three in
the morning, without a development environment.

---

## Exporting a copy and using it

```bash
ssh-crypto-checker --export-policy mi-politica.json
ssh-crypto-checker --config mi-politica.json servidor.example.com
```

`--export-policy` writes **the file and its `profiles/` directory next to it**,
because a policy without standards raises no error: it looks exactly like a
scan against standards that everyone passes. The two travel together.

It refuses to overwrite what is already there. A second export into the same
directory is allowed (a strict policy and a lax one sharing
one set of standards is how the installed tree itself is laid out); what is
rejected is stomping on a standard file **that says something else**, and the
rejection happens before anything is written.

## Where the tool looks, in order

1. Whatever `--config` says.
2. The `SSH_CRYPTO_CHECKER_CONFIG` environment variable.
3. `./ssh-crypto-checker.json`, in the current directory.
4. `~/.config/ssh-crypto-checker/algorithms.json`
5. `/etc/ssh-crypto-checker/algorithms.json`
6. The copy that ships with the package.

`--show-policy` says which one is being used and shows the order with an
asterisk on the winner. A policy **pinned by the environment variable but
missing is an error**, not a silent fallback to the stock one: pinning a
policy has to mean that policy was used.

## Formats

Always JSON. TOML if the interpreter is 3.11 or newer, and YAML if PyYAML is
installed — in both cases, when it cannot be done, the message says so instead
of failing in a strange way.

---

## The seven things inside

| Key | What it defines | Manual |
|---|---|---|
| `algorithms` | The five algorithm classes, with their entries, patterns, categories and tags. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| `categories` | What each category means (`recommended`, `weak`, `insecure`…) and how many points it is worth. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| `vulnerabilities` | The known vulnerabilities and how each one is detected. | [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) |
| `sshd_config_checks` / `ssh_config_checks` | Checks on server and client directives. | [`politica-configuracion.md`](politica-configuracion.md) |
| `scoring` | Per-class weights, modifiers, the grade scale and **grade caps**. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `requirements` and `security_strength` | Minimum key sizes and the strength bands in bits. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `profiles/` (directory) | The standards: one per directory, one edition per file. | [`politica-normativas.md`](politica-normativas.md) |

Also: `schema_version` (must start with `1.`), `metadata` (what
`--show-policy` shows about the file's origin) and `tag_labels`, which gives
each tag a readable name.

---

## How what you write is checked

**The loader is strict on purpose and always says which key is wrong.** A
three-thousand-line file is not something you debug by bisection:

```
mi-politica.json: vulnerabilities[7].detection: unknown condition 'presnt'
```

Rules that are surprising, and deliberately so:

- **The five algorithm classes are mandatory.** Deleting one does not mean
  "I don't care about that class"; it means a server could offer anything at
  all there without anyone saying a word.
- **The grade scale cannot be empty.**
- **A duplicate identifier is rejected**: two detections with the same `id`
  cannot both be reported.
- **A grade-cap `when` that does not exist is rejected**, with the list of the
  ones that do. A cap that never fires because of a typo is worse than not
  having one.
- An **algorithm the policy does not know** is not an error: servers offer
  names nobody has catalogued all the time. It comes out as
  *unknown*, which is an answer.

Always test what you edit before trusting it:

```bash
ssh-crypto-checker --config mi-politica.json --show-policy
ssh-crypto-checker --config mi-politica.json --list-vulnerabilities
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --no-color
```

---

## The rule you should not break

**Do not invent content.** If you add a vulnerability, put in the real
reference. If you encode a standard, read it first. A policy file with
invented entries produces reports that someone is going to believe, and
whoever wrote them is not the one who pays for the damage.
