---
layout: post
title: "Shift Left: Setting Up a DevSecOps Lab with Semgrep and Gitleaks"
date: 2026-10-15 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, semgrep, gitleaks, pre-commit, sast, secrets]
description: "A hands-on guide to a local DevSecOps lab: pre-commit hooks that run Gitleaks and Semgrep on every git commit, using OWASP Juice Shop as the target."
---

Most security findings are cheap to fix the moment they are written and expensive to
fix once they ship. A leaked key in a commit is a five-second mistake that turns into
a rotation incident. An injectable query is a one-line shortcut that becomes a
production vulnerability. Both are usually caught far too late — if at all — because
the scanner only runs after the code is merged.

This post is about the first piece of a **shift-left DevSecOps lab**: a local gate
that runs on every `git commit`, using [Gitleaks](https://github.com/gitleaks/gitleaks)
for secrets and [Semgrep](https://semgrep.dev) for static analysis, wired together with
[pre-commit](https://pre-commit.com). It is the setup I use to practice on
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop).

## Why a local lab, and why commit-time?

The cheapest bug is the one that never leaves your laptop. A commit hook gives you the
fastest possible feedback loop:

- The developer still has the file open in the editor, so the fix is trivial.
- Nothing enters CI, so you are not waiting on a pipeline to tell you about a typo.
- Secrets never leave the workstation. Once a token is pushed it is compromised, even
  if you force-push it away — it lives on in forks and the reflog.

The rule of thumb: block locally what you can, and keep CI as the guarantee for what
you cannot (cross-file dataflow, dependency CVEs, container layers).

## The target

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is an intentionally
insecure web app — perfect for a lab, because the findings are real and deliberate. It
uses TypeScript, Express, Sequelize, and Angular, and ships with the classic
vulnerabilities in plain sight. We will point our scanner at it and watch it work.

## The tools

| Tool | Role | Why |
| --- | --- | --- |
| pre-commit | Orchestration | Manages hook versions and builds an isolated environment per tool |
| Gitleaks | Secrets scanning | Regex + entropy detection, with allowlists |
| Semgrep | SAST | Pattern- and dataflow-based analysis, extensible with custom rules |

## Step 1 — Install the tools

Install `pre-commit` and `semgrep` with `pipx` so they live in isolated environments:

```bash
pipx install pre-commit
pipx install semgrep
```

Install `Gitleaks` from its release (or build it with Go):

```bash
# via Go
go install github.com/zricethezav/gitleaks/v8@latest

# or grab the release binary
curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
  | tar -xz -C /usr/local/bin gitleaks
```

Confirm everything is on your `PATH`:

```bash
gitleaks version
semgrep --version
pre-commit --version
```

## Step 2 — Write the gate config

`pre-commit` reads a single version-controlled file. Each hook is pinned to a release
so the results are reproducible, and the tool environments are built once and cached.

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

- `Gitleaks` scans the **staged** changes, so it checks exactly what the commit will
  contain.
- `Semgrep` is capped at `--severity=ERROR` and `--error`, so only high-severity
  findings fail the build. Warning-level noise is reported but does not block anyone.

## Step 3 — Install the hook

```bash
pre-commit install
```

From now on the gate runs automatically on every commit. To run it on demand across
the whole repo:

```bash
pre-commit run --all-files
```

## Step 4 — Prove it blocks

The only way to trust a gate is to watch it stop something. Stage a fake token:

```bash
printf 'GITHUB_TOKEN="ghp_zJ4Q2W7X9PLM3NRTpvK8sD1fG6hB0cXab12cd"\n' > test-secret.env
git add test-secret.env
git commit -m "oops"
```

Gitleaks flags the `github-pat` pattern and the commit is **aborted** with a non-zero
exit code. Delete the file, rotate the credential, retry — and the gate passes. That
failure is the feature.

## Step 5 — Add a custom Semgrep rule

Off-the-shelf rulesets are good, but writing your own is where SAST clicks. Every
injection detector is really a **source → sink → sanitizer** model: where untrusted
data enters, the dangerous operation, and whatever makes the data safe.

```yaml
rules:
  - id: sqli-string-built-query
    languages: [typescript, javascript]
    severity: ERROR
    message: SQL query built with string interpolation. Use parameterized queries.
    patterns:
      - pattern-either:
          - pattern: $DB.query(`...${$INPUT}...`, ...)
          - pattern: $DB.query("..." + $INPUT + "...", ...)
    metadata:
      cwe: "CWE-89: SQL Injection"
```

In Semgrep's pattern language `$X` matches any single expression and `...` matches any
sequence, so a template literal containing an interpolation inside a `query(...)` call
is flagged regardless of what the database object is named.

## Keeping the gate trustworthy

A gate that cries wolf gets disabled. Two levers keep it useful:

- **Scope it.** Allowlist test fixtures in the secrets config and exclude test data
  and the intentionally-vulnerable challenge snippets from Semgrep, so real code stays
  loud and scaffolding stays quiet.
- **Severity-gate the hook.** Only `ERROR` fails the commit. Everything else is
  informative, so nobody learns to reflexively type `--no-verify`.

When a true positive appears, the workflow is always the same: read the rule ID and
location, fix the code, rotate anything already exposed, and only then decide whether
a legitimate exception belongs in an allowlist — never a broad one.

## What I took away

- **Detection belongs as close to the author as possible.** The cheapest bug is the one
  that never leaves the laptop.
- **Secrets and injection are different detectors with different logic.** Entropy and
  regex for one; source/sink dataflow for the other.
- **Custom rules force you to understand the bug class.** Writing the rule taught me
  more about injection than reading ten advisories.
- **A gate must be fast and quiet to survive.** Pin versions, isolate environments,
  gate on severity, and triage false positives instead of disabling the hook.

Next up in the lab: carrying the same checks into CI so nothing that bypasses the local
hook slips through, then adding dependency (SCA) and container scanning.

— Yogender
