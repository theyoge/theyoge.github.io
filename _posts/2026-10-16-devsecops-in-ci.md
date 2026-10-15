---
layout: post
title: "From Local to CI: Running Your DevSecOps Gate on Every Pull Request"
date: 2026-10-16 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, github-actions, ci, semgrep, gitleaks, trivy, sarif]
description: "Move the local commit gate into GitHub Actions: run Gitleaks, Semgrep, and Trivy on every PR, surface findings as SARIF annotations, and make the check required."
---

<img class="post-hero" src="/assets/img/devsecops-in-ci.svg" alt="The DevSecOps gate running in CI: trigger on PR and push, same config, SARIF annotations, required check" width="1200" height="380">

In the [previous post](/writeups/shift-left-devsecops-lab/) we built a local gate that
runs Gitleaks, Semgrep, and Trivy on every `git commit`. That is a great habit, but a
local hook is only as reliable as the person running it. This post moves the same gate
into **GitHub Actions**, so it runs for every change on a clean machine nobody can skip.

## Why the local hook is not enough

A commit hook is easy to bypass or forget:

- Anyone can type `git commit --no-verify` and sail straight past it.
- A fresh clone has no hooks installed until you run `pre-commit install`.
- Every developer's machine has different tool versions — or no tools at all.

CI fixes all three. It runs on a **clean, consistent machine**, it runs for **every**
change, and — the important part — it can be made **required**, so a pull request
cannot merge until it passes.

The mental model: **local is a courtesy, CI is the guarantee.** Keep both. The local
hook gives you fast feedback while the file is still open; CI is the backstop that
nobody can skip.

## Two ways to run the gate in CI

| Approach | What it does | When to use |
| --- | --- | --- |
| `pre-commit/action` | Runs your existing `.pre-commit-config.yaml` on all files | Reuse the local config, zero duplication |
| Dedicated actions | `trivy-action`, a Semgrep run, `gitleaks-action` | Better reporting, SARIF, per-tool control |

We will use **both**: `pre-commit/action` for the secrets + SAST gate (it reuses the
config we already wrote), and the Trivy action because it can emit **SARIF**, which
GitHub turns into inline annotations. This is the same "split by weight" idea from the
first post, just moved to CI.

## The workflow file

Create `.github/workflows/devsecops.yml`:

```yaml
name: devsecops

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: devsecops-${{ github.ref }}
  cancel-in-progress: true

jobs:
  gate:
    name: secrets + sast (pre-commit)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: pre-commit/action@v3.0.1

  trivy:
    name: dependencies (trivy)
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scanners: vuln,secret,misconfig
          severity: HIGH,CRITICAL
          format: sarif
          output: trivy.sarif
          exit-code: "1"
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy.sarif
```

## Reading the workflow, line by line

- **`on:`** — run on every pull request and on pushes to `main`. PRs are where you want
  the gate; `main` catches anything that slipped in.
- **`permissions: contents: read`** — the default `GITHUB_TOKEN` starts at
  least-privilege. Only the Trivy job asks for `security-events: write`, which it needs
  to upload SARIF.
- **`concurrency`** — if you push twice quickly, cancel the older run. Saves minutes.
- **`actions/checkout`** — CI starts with an empty workspace; this pulls your code in.
- **`pre-commit/action`** — installs and runs your config. No duplicated tool list: it
  reads the exact `.pre-commit-config.yaml` from the first post.
- **`exit-code: "1"`** — Trivy fails the job on HIGH/CRITICAL. Combined with
  `if: always()` on the upload step, the SARIF is still published even when the scan
  fails.

## What SARIF buys you

**SARIF** is a standard JSON format for static-analysis results. Once you upload it to
GitHub code scanning, findings stop being a wall of console text and become:

- **Inline annotations** on the exact line in the PR diff,
- a running list under the repo's **Security → Code scanning** tab,
- automatically closed when the finding is fixed.

That is why the dedicated actions are worth it in addition to `pre-commit/action`: the
gate blocks, and SARIF explains *where* and *why*.

## Make it required

A workflow that can fail but is not enforced is decoration. In the repo, go to
**Settings → Branches** (or **Rulesets**) and add a branch protection rule for `main`
requiring the `devsecops` checks to pass before merging. Now a failing scan is a hard
stop, not a suggestion.

For the gate specifically, this is the payoff of the whole series so far: secret and
vulnerability scanning that **nobody can bypass**.

## Secrets and tokens in CI

Two rules that prevent the most common CI mistakes:

- **Never hardcode a token in the workflow.** Use the built-in
  `${{ secrets.MY_TOKEN }}` (Settings → Secrets and variables → Actions), and never
  echo it in logs.
- **Prefer short-lived credentials.** Anything that needs to push, or reach a cloud
  provider, should use **OIDC** (`permissions: id-token: write`) instead of a long-lived
  key. That is a story for a later post, but the habit starts here.

One quirk worth knowing: Gitleaks scans *staged* changes locally, but in CI there is no
staging area — `pre-commit/action` runs it across the checked-out tree, which is what
you want on a pull request.

## Keeping it fast

- Cache is handled by `pre-commit/action` automatically.
- Run the heavy Trivy job only where it matters (it is fine on every PR; it is not fine
  on every commit).
- Use `cancel-in-progress` so you never pay for a run that is already obsolete.

## What I took away

- **Local catches it early; CI makes it mandatory.** Keep the hook for feedback, but
  never rely on it as the only control.
- **Reuse the config.** Pointing CI at the same `.pre-commit-config.yaml` means one
  source of truth for what the gate checks.
- **Format matters for adoption.** SARIF turns a failing check into a line-level
  annotation, which is what developers actually act on.
- **Enforcement is a settings change, not a script.** Required checks are what convert
  a scan into a guarantee.

Next up: the local half, done properly — `pre-commit` hook **stages**, custom hooks, and
keeping the gate fast enough that people leave it on.

— Yogender
