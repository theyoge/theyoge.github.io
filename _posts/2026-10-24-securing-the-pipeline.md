---
layout: post
title: "Securing the Pipeline Itself: Pinned Actions, Least-Privilege Tokens, OIDC, and Provenance"
date: 2026-10-24 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, supply-chain, ci, github-actions, slsa, oidc]
description: "Your scanners run inside the CI pipeline — so the pipeline is attack surface too. Pin actions, shrink tokens, replace static cloud keys with OIDC, and prove what you shipped."
---

<img class="post-hero" src="/assets/img/pipeline-security.svg" alt="Securing the CI pipeline: pin actions, least-privilege tokens, OIDC, and provenance" width="1200" height="380">

We built a gate and ran it [in CI](/writeups/devsecops-in-ci/). Now a question that is
easy to skip: **who guards the guard?** The pipeline that runs your scanners holds
deploy credentials and the power to ship code. If an attacker can influence it, your
security checks become theatre — they can simply make the gate pass. Securing the build
system is the most underrated part of shift-left security.

## Why the pipeline is a target

CI is attractive precisely because it is trusted:

- It **holds secrets** — deploy tokens, registry credentials, cloud keys.
- It **runs code you did not write** — third-party actions and, on pull requests, code
  from other people.
- It **has authority** — it can push images, deploy, and change production.

Every one of those is an opportunity.

<figure class="post-figure">
  <img src="/assets/img/pipeline-flow.svg" alt="Hardening steps: pin actions to a commit SHA, read-only token, OIDC credentials, an approved environment, and a signed artifact" width="1200" height="260">
  <figcaption>Figure 1 — Hardening the pipeline, one control at a time.</figcaption>
</figure>

## The attack surface, itemised

- **Third-party actions** — anyone can publish one; a tag can be moved to malicious code.
- **The `GITHUB_TOKEN`** — the built-in token your workflow runs with.
- **Static cloud credentials** — long-lived AWS/GCP keys stored as repository secrets.
- **Secrets in general** — environment variables, logs, cache.
- **Fork PRs** — untrusted code that may run with your secrets if you are careless.
- **Artifacts** — what you build, and whether anyone can swap it afterwards.

## Control 1 — Pin actions to a commit SHA

A GitHub Action referenced by tag (`@v4`) is a **moving target**: whoever owns the action
can repoint `v4` to different code tomorrow, and your workflow will run it. Pin the full
commit SHA instead:

```yaml
# moving: can change under you
- uses: actions/checkout@v4

# pinned: this exact commit, forever
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

Automate the updates so pinning does not rot: enable **Dependabot for `github-actions`**
and it will open PRs to bump the SHAs. The same logic applies to container images — pin
by **digest**, as covered in the [container post](/writeups/container-hardening/).

## Control 2 — Least-privilege tokens

By default a workflow's token can be broad. Start from nothing and grant per job:

```yaml
permissions: {}          # deny everything at the top

jobs:
  scan:
    permissions:
      contents: read     # this job only needs to read code
```

A scanner needs to *read*. It does not need to write packages or deployments. The smaller
the token, the smaller the blast radius if a step is compromised.

## Control 3 — OIDC instead of static cloud keys

Storing a long-lived AWS key as a repository secret means a leak is permanent until you
notice and rotate. **OpenID Connect** removes the secret entirely: the workflow requests
a short-lived token from GitHub, and the cloud provider trusts it for one run.

```yaml
jobs:
  deploy:
    permissions:
      id-token: write      # allow the workflow to request an OIDC token
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@<sha>
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci-deploy
          aws-region: eu-west-1
```

There is no key to leak, no rotation to forget, and the credential expires in minutes.

## Control 4 — Treat fork PRs as hostile

Code from a fork is attacker-controlled. Two rules:

- Run untrusted workflows on `pull_request` (read-only token, no secrets), **never**
  `pull_request_target` with a checkout of the untrusted code.
- Require **environment approvals** before any job that touches production secrets.

Secrets are also easy to leak by accident: never print them, and remember that anything
echoed to logs is visible to anyone who can read the run.

## Control 5 — Prove what you shipped

Pinning and least privilege protect *how* you build. **Provenance** describes *what* came
out. SLSA-style attestations record which workflow, repository, and commit produced an
artifact, and they can be verified before deploy:

```yaml
      - uses: actions/attest-build-provenance@<sha>
        with:
          subject-path: dist/app.tar.gz
```

Combine this with image signing from the [container post](/writeups/container-hardening/),
and "only artifacts our pipeline produced may be deployed" becomes an enforceable rule
rather than a hope.

## Control 6 — Runner and cache hygiene

- Prefer GitHub-hosted runners for untrusted work; a compromised **self-hosted** runner
  can persist between jobs.
- Do not cache secrets; treat caches as potentially poisoned and scope them narrowly.
- Give each workflow only the tools it needs.

## What I took away

- **The pipeline is a trusted system, so it is a target.** If it is compromised, every
  check downstream is suspect.
- **Pinned SHAs and least-privilege tokens are cheap and high-impact.** Do them first.
- **OIDC deletes a whole class of leak** by replacing static keys with short-lived ones.
- **Provenance makes trust verifiable.** "We built it" becomes something you can prove.

Next up: the secret handling that ties all of this together — from detecting a leak to
preventing one.

— Yogender
