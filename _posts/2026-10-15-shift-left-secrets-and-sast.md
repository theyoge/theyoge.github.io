---
layout: post
title: "Shift Left: Blocking Secrets and SQL Injection Before They're Committed"
date: 2026-10-15 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, semgrep, gitleaks, pre-commit, sast, secrets]
description: "Wiring gitleaks and Semgrep into a pre-commit gate, then writing a custom rule to catch SQL injection in OWASP Juice Shop."
---

Most security findings are cheap to fix the moment they are written and expensive to
fix once they ship. A leaked key in a commit is a five-second mistake that turns into
a rotation incident. An injectable query is a one-line shortcut that becomes a
production vulnerability. Both are caught far too late — if at all — because the
scanner only runs after the code is merged.

This is a writeup of a small project I put together to move detection to the left:
a **local gate that runs on every `git commit`**, backed by two tools that cover the
two most common classes of bug I care about — **hardcoded secrets** and **injection**
— plus the one custom rule I wrote to make it useful.

## Why commit-time?

CI scanners are the safety net; a commit hook is the front door. The advantages are
practical, not philosophical:

- **Fastest possible feedback.** The developer still has the file open in the editor.
- **The fix is trivial while the change is in flight.** No branch rebuild, no pipeline
  wait, no context switch.
- **Secrets never leave the workstation.** Once a token is pushed, it is compromised,
  even if you force-push it away — it lives in the reflog, in forks, and in GitHub's
  object store until it is garbage-collected.

The rule of thumb: block locally what you can, and keep CI as the guarantee for the
things you cannot (cross-file taint, dependency CVEs, container layers).

## The target

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is an intentionally
insecure web app — perfect for tuning detectors, because the findings are real and
deliberate. It uses TypeScript, Express, Sequelize, and Angular, and ships with the
classic vulnerabilities in plain sight. Two in particular anchor this writeup:

```ts
// routes/login.ts — string-built SQL
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

```ts
// routes/search.ts — user input into a LIKE clause
let criteria: any = req.query.q ?? ''
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

## The stack

| Tool | Role | Why |
| --- | --- | --- |
| [pre-commit](https://pre-commit.com) | Orchestration | Manages hook versions and creates an isolated environment per tool |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets scanning | Regex + entropy detection, with allowlists |
| [Semgrep](https://semgrep.dev) | SAST | Pattern- and dataflow-based static analysis, extensible with custom rules |

## Wiring the gate

`pre-commit` reads a single version-controlled file. Each hook is pinned to a release
so results are reproducible, and the tool environments are built once and cached.

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
        args: ["--config", ".gitleaks.toml"]

  - repo: https://github.com/semgrep/semgrep
    rev: v1.180.0
    hooks:
      - id: semgrep
        args:
          - "--config=auto"
          - "--severity=ERROR"
          - "--error"
```

Two details worth calling out:

- `gitleaks` scans the **staged** changes (`--staged`), so it checks exactly what the
  commit will contain.
- `semgrep` is capped at `--severity=ERROR` and `--error`, so only *high*-severity
  findings fail the commit. Warning-level noise is reported but does not block anyone.

Install it once:

```bash
pre-commit install
```

The hook now runs automatically. To prove it actually blocks, stage a fake token:

```bash
printf 'GITHUB_TOKEN="ghp_zJ4Q2W7X9PLM3NRTpvK8sD1fG6hB0cXab12cd"\n' > test-secret.env
git add test-secret.env
git commit -m "oops"
```

gitleaks flags the `github-pat` pattern and the commit is **aborted** with a non-zero
exit code. Delete the file, rotate the credential, retry — and the gate passes. That
failure is the feature.

## A custom rule for SQL injection

Off-the-shelf rulesets are good, but writing your own is where SAST clicks. Every
injection detector is really a **source → sink → sanitizer** model:

- **Source** — where untrusted data enters (`req.query`, `req.body`, `req.params`).
- **Sink** — the dangerous operation (a raw SQL `query`).
- **Sanitizer** — anything that makes the data safe (parameter binding, escaping).

### Approach 1 — pattern matching (syntactic)

The cheapest detector looks for the *shape* of the bug: a SQL string built with
interpolation or concatenation.

```yaml
rules:
  - id: sqli-string-built-query
    languages: [typescript, javascript]
    severity: ERROR
    message: >-
      SQL query built with string interpolation/concatenation. Use parameterized
      queries instead.
    patterns:
      - pattern-either:
          - pattern: $DB.query(`...${$INPUT}...`, ...)
          - pattern: $DB.query("..." + $INPUT + "...", ...)
          - pattern: $DB.query('...' + $INPUT + '...', ...)
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
```

In Semgrep's pattern language, `$X` is a metavariable matching any single expression
and `...` matches any sequence. So `$DB.query(`...${$INPUT}...`)` matches *any* method
named `query` on *any* object whose argument is a template literal containing an
interpolation. It flags both Juice Shop sinks above, and correctly ignores the
parameter-free `query('SELECT sql FROM sqlite_master')` two lines later.

### Approach 2 — taint mode (dataflow)

Patterns don't know whether the interpolated value is *actually* user input. Taint
mode does, because it tracks data from source to sink and stops at sanitizers:

```yaml
rules:
  - id: sqli-taint
    languages: [typescript]
    severity: ERROR
    message: User-controlled input reaches a raw SQL query.
    mode: taint
    pattern-sources:
      - pattern: req.query.$P
      - pattern: req.body.$P
      - pattern: req.params.$P
    pattern-sinks:
      - pattern: $DB.query($QUERY, ...)
    pattern-sanitizers:
      - pattern: $DB.escape(...)
    metadata:
      cwe: "CWE-89: SQL Injection"
```

Because taint follows intermediate variables, this catches the `search.ts` case where
`criteria` is assigned from `req.query.q` and only later interpolated. The important
limitation to know: **Semgrep OSS taint analysis is intra-procedural** — it tracks data
within a single function. Send the value through a helper in another file and it will
not follow. That is exactly why a cheap pattern rule is worth keeping in the toolbox
alongside the precise one.

## Triage, and keeping the gate trustworthy

A gate that cries wolf gets disabled. Two levers keep it useful:

- **Scope it.** The secrets allowlist ignores fixtures and specs; the Semgrep ignore
  file skips test data and the intentionally vulnerable challenge snippets, so real
  code stays loud and test scaffolding stays quiet.
- **Severity-gate the hook.** Only `ERROR` fails the commit. Everything else is
  informative, so the team never learns to reflexively type `--no-verify`.

When a true positive appears, the workflow is the same every time: read the rule ID
and location, fix the code (parameterize the query, move the secret to a vault),
rotate anything already exposed, and only then decide whether a legitimate exception
belongs in an allowlist — never a broad one.

## What I took away

- **Detection belongs as close to the author as possible.** The cheapest bug is the
  one that never leaves the laptop.
- **Secrets and injection are different detectors with different logic.** Entropy and
  regex for one; source/sink dataflow for the other.
- **Custom rules force you to understand the bug class.** Writing the SQLi rule taught
  me more about injection than reading ten advisories.
- **A gate must be fast and quiet to survive.** Pin versions, isolate environments,
  gate on severity, and triage false positives instead of disabling the hook.

Next up: carrying these same checks into CI so nothing that bypasses the local hook
slips through, and extending the rule pack to API and template-injection sinks.

— Yogender
