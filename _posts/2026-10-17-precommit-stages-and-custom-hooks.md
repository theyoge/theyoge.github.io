---
layout: post
title: "pre-commit, For Real: Hook Stages, Custom Hooks, and Keeping It Fast"
date: 2026-10-17 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, pre-commit, git-hooks, automation]
description: "Go beyond a single pre-commit file: use hook stages to split fast and heavy checks, write your own local hooks, and keep the gate fast enough that nobody disables it."
---

<img class="post-hero" src="/assets/img/precommit-stages.svg" alt="pre-commit hook stages: fast checks on commit, message checks, heavy checks on push, and manual runs" width="1200" height="380">

The [first post](/writeups/shift-left-devsecops-lab/) wired Gitleaks and Semgrep into
`pre-commit`, and the [second](/writeups/devsecops-in-ci/) carried the same config into
CI. This one is about the tool itself: how `pre-commit` decides *when* to run each
hook, how to write your own, and how to keep the whole thing fast enough that people
leave it turned on.

## Hook stages: the same tool at different moments

`pre-commit` can hook more than the commit. Each hook declares one or more **stages**,
which map to Git events:

| Stage | Runs on | Good for |
| --- | --- | --- |
| `pre-commit` | `git commit` | Fast checks: secrets, formatting, SAST |
| `commit-msg` | after you write the message | Enforcing a commit-message convention |
| `pre-push` | `git push` | Heavy checks: SCA, container scans |
| `manual` | `pre-commit run <id>` | On-demand, never automatic |

The default stage is `pre-commit`, so the hooks from the first post already run there.
You can change the default for the whole file with `default_stages`, and override it per
hook with `stages:`.

## Split fast from heavy

The single most useful habit is to keep `commit` fast and push the slow stuff to
`pre-push`. Secrets and SAST run in a second or two; a Trivy scan downloads and
refreshes a vulnerability database and does not belong on every keystroke-adjacent
commit.

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

Install the push-stage hook too — it is a separate Git hook file:

```bash
pre-commit install --hook-type pre-push
```

## A `commit-msg` hook

Message linting is the same mechanism against a different file. Here is a tiny
conventional-commit check written inline as a local hook using the `fail` language
(which does nothing but exit non-zero):

```yaml
  - repo: local
    hooks:
      - id: conventional-commit
        name: conventional commit message
        entry: conventional commit message required (feat|fix|docs|chore): ...
        language: fail
        stages: [commit-msg]
```

`pre-commit` passes the path to the commit-message file as an argument, so real message
hooks read that file and validate it. This example uses `language: fail` purely to show
that the *stage* is the point — the hook runs against the message, not the code.

## Writing your own local hook

Not every check has a published hook. `repo: local` lets you wrap any command you like.
The important keys:

- **`language`** — `system` runs a binary already on `PATH`; `script` runs a file from a
  `scripts/` folder in the hook repo; `python`/`node` install dependencies for you.
- **`entry`** — the command to run. `pre-commit` appends the matching filenames unless
  you say otherwise.
- **`files` / `exclude`** — regular expressions limiting which files trigger the hook.
- **`pass_filenames`** — set `false` when your tool wants to discover files itself.
- **`always_run`** — run even when no files match (remember `Gitleaks` needed this,
  because it scans the staged area itself).

A concrete example — fail if any file is committed with a trailing whitespace-only
change, using a script:

```yaml
  - repo: local
    hooks:
      - id: no-debug
        name: block leftover debugger statements
        entry: scripts/check-debug.sh
        language: script
        files: \.(js|ts)$
```

`pre-commit` passes the matched filenames to the script, and any non-zero exit blocks
the commit.

## The full config

Putting it together — a config that splits by stage, wraps a local check, and reuses
the pinned community hooks:

```yaml
default_stages: [pre-commit]

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
        args: ["--config=auto", "--config=rules/sqli.yaml", "--severity=ERROR", "--error"]

  - repo: local
    hooks:
      - id: no-debug
        name: block leftover debugger statements
        entry: scripts/check-debug.sh
        language: script
        files: \.(js|ts)$

      - id: trivy-fs
        name: trivy (dependencies & secrets)
        entry: trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 --quiet
        language: system
        pass_filenames: false
        stages: [pre-push]
```

## Speed and hygiene

- **Bump hooks deliberately.** `pre-commit autoupdate` moves every `rev` to the latest
  release — read the diff, then commit it. Pinned versions are what make the gate
  reproducible.
- **Run a subset while working.** `pre-commit run gitleaks --files app.ts` runs one hook
  on one file; `--all-files` is for CI, not your inner loop.
- **Clean when things break.** `pre-commit clean` wipes the cached environments; the next
  run rebuilds them.
- **Let CI fill the gap.** `pre-commit.ci` (or your own workflow) runs `--all-files` on
  every PR, so even a change that skipped the local hook is checked.

## The `--no-verify` problem

`--no-verify` is an escape hatch, and a gate that people feel a need to escape is a gate
that is too slow or too noisy. Two policies keep it healthy:

- Treat `--no-verify` as an exception to explain in the PR, not a habit.
- Fix the root cause: if a hook is slow, move it to `pre-push`; if it is noisy, tune the
  allowlist or the severity threshold.

The rule of thumb from the whole series: **the hook should be fast enough that you never
want to skip it.**

## What I took away

- **Stages are the design tool.** Choosing *when* a check runs — commit, message, push —
  is more important than choosing the tool.
- **`repo: local` makes any command a hook.** You are never limited to what someone else
  published.
- **A gate is a product, not a script.** Speed, noise, and escape hatches determine
  whether it survives contact with a team.

Next up: taking the local gate apart — dependency scanning in depth, SBOMs, and knowing
which CVEs actually matter.

— Yogender
