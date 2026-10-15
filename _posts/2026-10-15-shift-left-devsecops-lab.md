---
layout: post
title: "Shift Left: Setting Up a DevSecOps Lab with Gitleaks, Semgrep, and Trivy"
date: 2026-10-15 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, semgrep, gitleaks, trivy, pre-commit, sast, sca, secrets]
description: "A beginner-friendly guide to a local DevSecOps lab: pre-commit hooks running Gitleaks, Semgrep, and Trivy on a commit, using OWASP Juice Shop as the target."
---

Most security findings are cheap to fix the moment they are written and expensive to
fix once they ship. A leaked key is a five-second mistake that turns into a rotation
incident. An injectable query is a one-line shortcut that becomes a production
vulnerability. Both are usually caught far too late — if at all — because the scanner
only runs after the code is merged.

This post walks through the first piece of a **shift-left DevSecOps lab** for people
who have never wired security tooling into a workflow before: a local gate that runs on
every `git commit`. It uses three scanners and one orchestrator, practiced on
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop).

## New to DevSecOps? A 30-second primer

"Security scans" is not one thing. The tools in this post cover three different layers,
and it helps to know which is which:

| Layer | Question it answers | Tool here |
| --- | --- | --- |
| Secrets scanning | Did I hardcode a key, token, or password? | Gitleaks |
| SAST (static analysis) | Is my *source code* unsecure (e.g. SQL injection)? | Semgrep |
| SCA (dependencies) | Does a library I depend on have a known CVE? | Trivy |
| Container & IaC | Is my image or infrastructure config unsafe? | Trivy |

"Shifting left" just means running these as early as possible — on your machine, at
commit time — instead of only in a pipeline after the code is already merged.

## What we are building

A **commit hook** that blocks a commit when a scanner finds something serious. We use
[pre-commit](https://pre-commit.com) as the orchestrator because it pins each tool to a
version and builds an isolated environment for it, so your machine stays clean and the
results are reproducible.

## The lab target

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is an intentionally
insecure web app — perfect for a lab, because the findings are real and deliberate. It
is TypeScript + Express + Sequelize + Angular, and it ships with the classic
vulnerabilities in plain sight, so our scanners have something to bite on.

## Where every file goes

For a beginner, the confusing part is not the tools — it is *where things live*. Here
is the full layout we build, all relative to the repo root:

```text
juice-shop/
├── .pre-commit-config.yaml     # the gate: which hooks run on commit
├── .gitleaks.toml              # Gitleaks settings + allowlist
├── .semgrepignore              # paths Semgrep should skip
├── .trivyignore                # accepted/ignored Trivy findings
└── rules/
    └── sqli.yaml               # YOUR custom Semgrep rule
```

Two rules of thumb: config files that a tool reads automatically start with a dot and
sit at the repo root (`.gitleaks.toml`, `.semgrepignore`, `.trivyignore`), and custom
rule files you author yourself go in a folder such as `rules/` so you can reference
them explicitly. We wire that reference in Step 5.

## Step 1 — Install the tools

Install `pre-commit` and `semgrep` with `pipx` (isolated environments for each):

```bash
pipx install pre-commit
pipx install semgrep
```

Install `gitleaks` from its release (or build it with Go):

```bash
go install github.com/zricethezav/gitleaks/v8@latest

# or download the release binary
curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
  | tar -xz -C /usr/local/bin gitleaks
```

Install `trivy`:

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

# or run it with Docker and skip installing entirely
docker run --rm -v "$PWD:/src" aquasec/trivy fs /src
```

Confirm everything is on your `PATH`:

```bash
gitleaks version
semgrep --version
trivy --version
pre-commit --version
```

## Step 2 — Write the gate config

Create `.pre-commit-config.yaml` at the repo root. Each hook is pinned to a release so
results are reproducible, and `pre-commit` builds the tool environments once and caches
them.

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
          - "--config=rules/sqli.yaml"
          - "--severity=ERROR"
          - "--error"
```

Three details worth calling out:

- `Gitleaks` scans the **staged** changes, so it checks exactly what the commit will
  contain, and reads our allowlist from `.gitleaks.toml`.
- `Semgrep` accepts `--config` more than once. Here it loads the community rules for
  the detected language (`auto`) **and** our own rule file at `rules/sqli.yaml`. This is
  the line that makes your custom rule run — without it, the file is just sitting there.
- `--severity=ERROR` plus `--error` means only high-severity findings fail the commit;
  warnings are reported but never block anyone.

## Step 3 — Install the hook

```bash
pre-commit install
```

That writes `.git/hooks/pre-commit`, which now runs the gate automatically. To run it
on demand across the whole repo instead of only staged files:

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
exit code. Delete the file, rotate the credential, retry — and the gate passes. The
failure is the feature.

## Step 5 — Write and wire a custom Semgrep rule

Off-the-shelf rulesets are good, but writing your own is where SAST clicks. Every
injection detector is really a **source → sink → sanitizer** model: where untrusted
data enters, the dangerous operation, and whatever makes the data safe.

Create the file `rules/sqli.yaml` (the `rules/` folder is ours; make it if it does not
exist):

```yaml
rules:
  - id: sqli-string-built-query
    languages: [typescript, javascript]
    severity: ERROR
    message: >-
      SQL query built with string interpolation. Use parameterized queries instead.
    patterns:
      - pattern-either:
          - pattern: $DB.query(`...${$INPUT}...`, ...)
          - pattern: $DB.query("..." + $INPUT + "...", ...)
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
```

Then make sure it is referenced in `.pre-commit-config.yaml` with
`--config=rules/sqli.yaml` (shown in Step 2). Once wired, it runs alongside the
community rules. In Semgrep's pattern language `$X` matches any single expression and
`...` matches any sequence, so a template literal containing an interpolation inside a
`query(...)` call is flagged no matter what the database object is named.

To test the rule alone while you are developing it:

```bash
semgrep scan --config rules/sqli.yaml routes/
```

## Step 6 — Add Trivy for dependency and container scanning

Gitleaks and Semgrep look at *your* code. Trivy looks at everything you *consume*: the
packages in your lockfiles, your container images, and your infrastructure config.

Scan the repository for vulnerable dependencies and secrets:

```bash
trivy fs --scanners vuln,secret,config .
```

Scan a built container image:

```bash
docker build -t juice-shop:local .
trivy image juice-shop:local
```

Fail only on the findings that matter and ignore accepted ones:

```bash
trivy fs --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore .
```

**Where should Trivy run?** Trivy downloads and refreshes a vulnerability database, so
it is slower than the other two tools. Running it on every `git commit` gets annoying
fast. In practice you run it in two better places:

- **A `pre-push` hook**, so it runs when you push rather than on every commit.
- **In CI**, on every pull request — the natural home for SCA, because dependency CVEs
  change even when your code does not.

If you still want it in the local gate, add a `pre-push` hook by creating a `local`
entry:

```yaml
  - repo: local
    hooks:
      - id: trivy-fs
        name: trivy (dependencies & secrets)
        entry: trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 --quiet
        language: system
        pass_filenames: false
        stages: [pre-push]
```

Install it for the push stage:

```bash
pre-commit install --hook-type pre-push
```

Note the difference from the first two hooks: `Gitleaks` and `Semgrep` run on `commit`
(fast, per-change), while `Trivy` runs on `push` (heavier, point-in-time). Splitting
them by stage is the single most useful habit for keeping a local gate usable.

## Keeping the gate fast and trustworthy

A gate that cries wolf or slows you down gets disabled. Three habits prevent that:

- **Split by stage.** Fast checks (secrets, SAST) on commit; heavy checks (SCA,
  containers) on push or in CI.
- **Scope it.** Allowlist test fixtures in `.gitleaks.toml`, exclude test data and the
  intentionally-vulnerable challenge snippets via `.semgrepignore`, and record accepted
  findings in `.trivyignore` — so real code stays loud and scaffolding stays quiet.
- **Gate on severity.** Only `ERROR`/`HIGH,CRITICAL` fails the build, so nobody learns
  to reflexively type `--no-verify`.

When a true positive appears, the workflow is always the same: read the rule ID and
location, fix the code, rotate anything already exposed, and only then decide whether a
legitimate exception belongs in an allowlist — never a broad one.

## What I took away

- **Detection belongs as close to the author as possible.** The cheapest bug is the one
  that never leaves the laptop.
- **Different layers need different tools.** Secrets, source, dependencies, and
  containers are four separate problems; no single scanner covers them all.
- **Custom rules force you to understand the bug class.** Writing the SQL injection rule
  taught me more about injection than reading ten advisories.
- **A gate must be fast and quiet to survive.** Pin versions, isolate environments,
  split by stage, gate on severity, and triage false positives instead of disabling.

Next up in the lab: carrying the exact same checks into CI so nothing that bypasses the
local hook slips through.

— Yogender
