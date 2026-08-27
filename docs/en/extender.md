# `docs/` — manuals for extending the tool

The [main README](README.md) explains how to **use** sshCryptoChecker.

There is one subdirectory:

- `estandares/` — the official documents (NIST, BSI,
  BOE, ANSSI, IETF…) that the compliance profiles come from, downloaded
  from their publisher's website, with the source URL and the fingerprint of each one.
These manuals explain how to **extend it**, and they are written so that someone
who does not know the code can write a plugin or a policy by reading only
this.

There are two ways to extend the tool, and the first question is which one you
need:

> **Just want to understand why your server got that grade?** You do not need
> any of these manuals: [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
> is the complete, public scoring system, with an example worked out
> step by step.

| You want to… | Then | Manual |
|---|---|---|
| Change which algorithms are good or bad, or what grade each thing gets | A **policy**. No Python is touched. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| Detect a new known vulnerability | Almost always a **policy**; a plugin only if the detection needs computation. | [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) |
| Check an `sshd_config` directive | A **policy**. | [`politica-configuracion.md`](politica-configuracion.md) |
| Measure against a standard (your own or a published one) | A **standards policy**. | [`politica-normativas.md`](politica-normativas.md) |
| Change how the grade is calculated | A **policy**. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| Check something that requires **code**: arithmetic, correlation across servers, a format that has to be parsed | A **plugin**. | [`plugins.md`](plugins.md) |

> **The rule, in one sentence:** if what you want to say can be written as
> data, write it as data. The policy file can be edited on a
> server at three in the morning; a plugin has to be deployed.

## Plugin manuals

| File | What it covers |
|---|---|
| [`plugins.md`](plugins.md) | **Start here.** The contract common to the three types: where the files go, what metadata is needed, what your function receives, what it can return, what a plugin **cannot** do, and how to test it. |
| [`plugin-check.md`](plugin-check.md) | Type `check`: looks at **one** server. It is 90% of the cases. |
| [`plugin-fleet.md`](plugin-fleet.md) | Type `fleet`: looks at **all** the servers in the scan at once. For what can only be seen by comparing. |
| [`plugin-vulnerability.md`](plugin-vulnerability.md) | Type `vulnerability`: a known vulnerability whose detection does not fit in the policy file. |

## Policy manuals

| File | What it covers |
|---|---|
| [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) | **The scoring system, whole and public.** How you get from the algorithms a server offers to a letter, why each thing weighs what it weighs, and the rule that keeps the grade and the verdict from contradicting each other. |
| [`politicas.md`](politicas.md) | **Start here.** What the policy file is, how to export a copy, where it is looked for, and the seven things that can be written in it. |
| [`politica-algoritmos.md`](politica-algoritmos.md) | The five algorithm classes, their entries, their patterns, their categories and their tags. |
| [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) | The complete detection grammar: by version, by algorithm, by configuration, and how they combine. |
| [`politica-configuracion.md`](politica-configuracion.md) | Checks on `sshd_config` and on the client's `ssh_config`. |
| [`politica-puntuacion.md`](politica-puntuacion.md) | Weights, modifiers, the grade scale, **grade caps** and security strength bands. |
| [`politica-normativas.md`](politica-normativas.md) | Compliance profiles: the two kinds, and one edition per file. |

## Audit

| File | What it covers |
|---|---|
| [`auditoria-integridad.md`](auditoria-integridad.md) | **Does everything the tool claims come from a document?** Audit (2026-08-13) of the 25 profiles and of the base policy against the documents in `estandares/`: what is backed, what rests on documents not yet archived, and what is our own methodology. |
