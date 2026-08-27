# Plugin guide — the common contract

A plugin is **one `.py` file** with a handful of constants and one function.
There is nothing to install, nowhere to register, and no classes to inherit
from.

This guide is the contract shared by all three kinds. After it, depending on
what you want to look at:

- [`plugin-check.md`](plugin-check.md) — one server.
- [`plugin-fleet.md`](plugin-fleet.md) — every server at once.
- [`plugin-vulnerability.md`](plugin-vulnerability.md) — a known vulnerability.

---

## The shortest plugin that works

```python
"""The server announces its exact version in the banner."""

ID = "banner-reveals-version"
NAME = "The banner reveals the exact version"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = "The server publishes its full version before authentication."
REMEDIATION = "Build with a reduced version string, or put a banner in front."

def check(server):
    if server.product_version:
        return [f"El banner dice {server.product} {server.product_version}"]
    return None
```

Save it as `banner_version.py` in any directory and run it:

```bash
ssh-crypto-checker servidor.example.com --plugin-dir ./mis-plugins
```

Check that it loaded before scanning anything:

```bash
ssh-crypto-checker --list-plugins --plugin-dir ./mis-plugins
```

---

## The metadata

Each plugin is a module with uppercase constants. Four of them are
**required**, and the loader rejects the file if any is missing:

| Constant | Required | What it is |
|---|---|---|
| `ID` | **yes** | Stable identifier of the finding. It appears in the report, in the JSON and in the SARIF, and it is what someone will use to suppress it or track it across scans. Do not change it lightly. |
| `NAME` | **yes** | Human-readable title. It is what gets read in the report. |
| `SEVERITY` | **yes** | `critical`, `high`, `medium`, `low` or `info`. Anything else is a load error listing the valid ones. |
| `DESCRIPTION` | **yes** | What the finding means. Write it for someone who does not know why they are seeing it. |
| `KIND` | no (`vulnerability`) | `check`, `fleet` or `vulnerability`. **Always set it**: the default is almost never the one you want. |
| `REMEDIATION` | no (`""`) | What to do about it. A finding without a remedy is a complaint. |
| `REFERENCES` | no (`[]`) | List of URLs or identifiers: the CVE, the RFC, the vendor advisory. |
| `AFFECTS` | no (`server`) | `server` or `client`. `client` is for what looks at the configuration of **this** machine. |
| `NEEDS` | no (`[]`) | What data the plugin needs. See below. |

## `NEEDS`: say what you need, instead of failing without saying so

Many checks only make sense if the scan collected a certain piece of data, and
those pieces of data are **optional** (`--sshfp`, `--audit-config`…). A plugin
that looks at data that was not collected and returns "nothing" is saying
"this server is fine" when it should be saying "I did not look".

That is why you declare it:

```python
NEEDS = ["sshfp", "host_keys"]
```

If the scan does not carry that data, your `check` **does not run**, and the
report says it could not be evaluated and which option would be needed to
repeat the scan. The valid names are exactly these, and any other is a load
error:

| Name | What the scan needs |
|---|---|
| `banner` | Always present if the server answered. |
| `kexinit` | The algorithm list. Always, if there was a negotiation. |
| `host_keys` | The host keys (collected by default; `--no-host-keys` removes them). |
| `auth_methods` | `--auth-methods` |
| `sshfp` | `--sshfp` |
| `known_hosts` | `--known-hosts` |
| `login_grace` | `--login-grace` |
| `max_startups` | `--max-startups` |
| `config` | `--audit-config` (authenticated audit of the server) |
| `client_config` | `--audit-client` |

---

## What `check` can return

All of this is valid, and the runner normalizes it:

| You return | It means |
|---|---|
| `None` or `False` or `[]` | There is nothing to report. **This is the normal case.** |
| `True` | Detected, with the module's metadata as is. |
| `["text", "text"]` | Detected, and those strings are the **evidence**. |
| `Detected(...)` | Detected, with evidence and optionally overriding severity, title, description, remediation or even the `ID`. |
| `Undetermined(needs=[...])` | **It could not be decided**, and this is what would resolve it. Not the same thing as saying no. |
| `Finding(...)` | A finding built by hand, if you need full control. |
| A list of any of the above | Several findings from a single file. |

```python
from ssh_crypto_checker.plugins import Detected, Undetermined

def check(server):
    if server.config is None:
        return Undetermined(needs=["config"])
    valor = server.directive("clientaliveinterval")
    if valor and int(valor) > 3600:
        return Detected(
            evidence=[f"ClientAliveInterval = {valor}"],
            severity="medium",          # graver than declared, in this case
            note="An hour is a long time for an idle session.",
        )
    return None
```

### Evidence is not decoration

`evidence` is the difference between "this server has a problem" and "this
server has *this* problem, look". Put in the concrete value that made it
fire: the algorithm, the directive and its value, the fingerprint. Whoever
reads the report has to be able to verify it without scanning again.

---

## The three things a plugin **cannot** do

These are not advice: they are guarantees verified by the test suite.

### 1. A plugin cannot change the grade

It receives a **view of observations**, not the result. It can see which
algorithms the server offers; it **cannot** see or touch the score, the
grade or the verdict. That is decided by the policy file.

The reason is simple: if a third-party plugin could move the grade, the
grade would stop meaning anything. An auditor has to be able to say "this A
comes from the policy, and the policy is right here".

### 2. A plugin cannot kill a scan

If your `check` raises an exception, it costs **its own result** and nothing
more: the report says that plugin failed on that server, and the scan goes
on. There is no need to wrap anything in `try`.

### 3. A plugin cannot put something into the report that the model forbids

A made-up severity or raw bytes where text belongs get normalized at the
boundary. That was not always so: a bad severity used to take down a target,
and stray bytes took down the whole scan.

---


## The architecture: what ships as a plugin, and what does not

**Almost every check the tool makes is a plugin.** It is not a third-party system
with the important things hidden elsewhere: it is the mechanism, and it is used.
Twelve built-in files, one per subject (`shared_host_keys` —fleet—,
`server_directives`, `server_files`, `server_accounts`, `client_audit`,
`auth_methods`, `host_certificates`, `sshfp_records`, `known_hosts_record`,
`preauth_capacity`, `rsa_key_quality`, `certificate_lifetime`); documented in
[`builtin/README.md`](../../ssh_crypto_checker/plugins/builtin/README.md).

Two things are **not** plugins, and the reason matters:

- **The 89 declarative JSON rules.** For matching a name, a version window or a
  directive value they are better than a plugin: no code, nothing executed,
  editable by non-programmers. A plugin is for what a rule *cannot express* —
  dividing a number, subtracting two dates, factoring a modulus.
- **The scoring model.** Algorithm classification, host-key size, effective
  strength, the grade and the profiles live in `assessment.py`, not in a plugin.
  `analysis.py` went from **2165 to 362 lines** when the checks were taken out of
  it, and it now emits none: what remains is the vulnerability engine's output,
  which are *engine results*, not judgements about a server.

### The two guarantees, tested and not assumed

The guarantees above — "a plugin cannot change the grade", "everything runs" —
are not trusted to discipline: they are pinned by tests, because they are the
kind that stop being true the moment someone adds a file.

- **No plugin can change the grade.** The test scans the same server with every
  plugin and with none, and requires `score`, `grade` and `verdict` to match —
  while also checking that the **findings do differ**, so the comparison is not
  vacuous. Another repeats it with a plugin that throws an exception.
- **Everything runs.** One test verifies that no plugin went uncalled, and
  another fails if someone puts a check back into `analysis.py`.

### Why there is no dependency system between plugins

There was a real ordering problem: plugins ran before the model computed the
post-quantum state and saw `None`. But the cause was **not a dependency between
plugins**: it was a single shared dependency, "after the model", resolved by
ordering the orchestrator. A graph would bring cycles, topological ordering and a
channel to pass data from one plugin to another — exactly the coupling to avoid.
If a plugin needs what another computes, the right answer is almost always to
**put that datum in the view**, where both read it without knowing each other. The
only ordering that exists is declarative and already in `KIND`: fleet plugins run
after server ones, because they cannot run before.

### The two examples that show the boundary

- **`rsa_key_quality`** divides the RSA key modulus by the primes under 1000 and
  checks the public exponent. Such a key is not *short*, it is **wrong**: it can
  be factored, and yet it advertises as a normal-sized `rsa-sha2-512`. No
  name-matching rule sees it.
- **`certificate_lifetime`** looks at **how long** a certificate was issued for.
  The policy can say when it expires *soon* (a comparison with today), but not for
  how long it was issued, because that is a subtraction. A ten-year certificate
  has given away exactly what a certificate buys over a bare key: that trust
  expires on its own.

---

## Where plugins are looked for, and what gets rejected

```bash
ssh-crypto-checker --plugin-dir ./mis-plugins servidor.example.com
```

`--plugin-dir` can be repeated. The default directories that `--list-plugins`
shows are searched as well.

**The working directory is never searched.** Running the tool from a
directory containing someone else's files must not mean loading someone
else's code.

A file or a directory **writable by group or others is rejected**, with the
reason. If anyone can edit the file, anyone can run code as whoever launches
the scan. The package's own `builtin/` directory is exempt, because its
integrity is that of the installation.

A plugin that fails to load **kills nothing**: the file and the reason are
reported, and the rest load. Always check with `--list-plugins`, which shows
the ones that loaded **and the ones that did not**.

---

## How to test your plugin

Against a real server you control, or against this repository's lab:

```bash
cd lab && ./lab-setup.sh && docker compose up -d --build && cd ..
ssh-crypto-checker 127.0.0.1:2222 --plugin-dir ./mis-plugins --no-color
```

And in a test, with no network, by handing it a hand-built view:

```python
import unittest
from ssh_crypto_checker.plugins import ServerView

import mis_plugins.banner_version as plugin


class ElBannerRevelaLaVersion(unittest.TestCase):
    def test_lo_dice_cuando_hay_version(self):
        class Banner:
            product = "OpenSSH"
            product_version = "9.6p1"

        resultado = plugin.check(ServerView(banner=Banner()))
        self.assertTrue(resultado)

    def test_calla_cuando_no_la_hay(self):
        self.assertFalse(plugin.check(ServerView()))
```

`ServerView()` with no arguments is a scan that collected nothing, and
**every** one of its accessors has an answer. It is the case most often
forgotten, and the one that breaks the most plugins written against a full
scan.

---

## Common mistakes

| Symptom | Cause |
|---|---|
| The plugin does not appear in `--list-plugins` | File or directory permissions: if group or others can write, it is rejected. Look at it with `ls -l`. |
| It shows up as rejected with "missing ID, NAME…" | One of the four required constants is missing. |
| "SEVERITY … is not one of" | Only `critical`, `high`, `medium`, `low`, `info`. |
| "NEEDS names …, which is not collected" | A `NEEDS` name that does not exist; the message lists the valid ones. |
| It never fires, and it should | Did you spell the algorithm class name right? `server.algorithms("cypher")` raises `ValueError` on purpose, precisely so it does not fail silently. |
| It fires on every server | You are probably returning `[]`, which is falsy — but `[""]` is truthy. |
