---
layout: post
title: "Secrets: From Detection to Prevention"
date: 2026-10-25 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, secrets, gitleaks, sops, vault, oidc]
description: "Detection is the smoke alarm; prevention is the fire code. How to find leaked secrets everywhere, respond correctly when one leaks, and stop putting them in code at all."
---

<img class="post-hero" src="/assets/img/secrets-prevention.svg" alt="Secrets lifecycle: detect, rotate first, purge history, and prevent" width="1200" height="380">

This series opened with [Gitleaks blocking a hardcoded token](/writeups/shift-left-devsecops-lab/),
and later posts added scanning [in CI](/writeups/devsecops-in-ci/) and handling secret
scanning [in the pipeline](/writeups/securing-the-pipeline/). But detection is only the
smoke alarm. This post is about the fire code: scanning the places people forget, reacting
correctly when a secret leaks, and — the real fix — **not putting secrets in code at all**.

## What a secret is

Anything that grants access: API keys, database passwords, signing keys, cloud
credentials, tokens, private keys. A secret in the wrong place is not a bug report, it is
an **active breach**, because anyone who finds it can use it.

## Detect everywhere, not just in the diff

A leak can sit in three places, and you need all three:

```bash
# 1. before it is committed (fast, staged)  -> the pre-commit hook
gitleaks git --pre-commit --redact --staged

# 2. across the repo in CI
gitleaks dir . --redact

# 3. across the FULL git history (the one everyone forgets)
gitleaks git --redact
```

The history scan matters because a secret deleted in a later commit is **still in the
earlier one**. It lives in the reflog, in forks, in clones, and in GitHub's object store.
Add GitHub's built-in **secret scanning + push protection**, which blocks known secret
patterns at push time — a second net under your own.

## When a secret leaks: the playbook

Order matters here, and most people get it backwards.

<figure class="post-figure">
  <img src="/assets/img/secrets-flow.svg" alt="Secret incident playbook: detect, rotate and revoke, purge history, prevent, and guard" width="1200" height="260">
  <figcaption>Figure 1 — The incident playbook. Rotation comes before history rewriting, always.</figcaption>
</figure>

1. **Rotate first.** Assume the secret is already copied. Generate a new credential and
   make the old one useless. This is the step that actually stops the breach.
2. **Revoke** the old secret so it cannot be used, even if it is still lying around.
3. **Then** purge history — `git filter-repo` (or BFG) to rewrite the commits — and force
   a coordinated push. Understand that rewriting does **not** un-leak: forks, caches, and
   clones may still hold it. That is why rotation came first.
4. **Prevent** the class of mistake (below).
5. **Guard** with push protection and pre-commit so it does not recur.

The one-line rule: **rotate, then rewrite.** Never the other way around.

## Prevention is the actual fix

Detection treats the symptom. The fix is to stop secrets from being in the repository in
the first place. Options, from weakest to strongest:

| Approach | How it works | Good for |
| --- | --- | --- |
| Env vars (local `.env`) | Loaded at runtime, git-ignored | local dev only |
| Cloud secret manager | Secrets fetched by name at runtime (AWS Secrets Manager, SSM) | app runtime |
| **SOPS + age** | Secrets encrypted *in the repo*, decrypted in CI | config that must be versioned |
| **Vault** | Issues **dynamic**, short-lived credentials | databases, cloud |
| **OIDC** | No secret at all — exchanged for a short-lived token | CI → cloud |

### Encrypting config with SOPS + age

Some configuration genuinely needs to live in the repo. Encrypt it so only CI (and people
with the key) can read it:

```bash
# one-time: generate an age key, commit only the PUBLIC key in .sops.yaml
age-keygen -o key.txt

# encrypt
sops --encrypt secrets.yaml > secrets.enc.yaml
git add secrets.enc.yaml         # safe to commit: ciphertext only

# decrypt at runtime (CI holds the private key as a protected secret)
sops --decrypt secrets.enc.yaml
```

The ciphertext is safe to commit; the private key lives in your secret manager or CI's
protected environment.

### Dynamic secrets with Vault

The strongest pattern is to have **no long-lived secret at all**. Vault can issue a
database credential that is valid for minutes and revoked automatically:

```bash
vault read database/creds/app-role
# username  v-app-role-4f2a9c
# password  A1b2C3...      valid for 1h, then gone
```

Nothing to leak, because the credential did not exist a moment ago and will not exist
soon.

### The best option: OIDC in CI

For pipelines, the cleanest answer is no stored cloud key at all — the [previous post](/writeups/securing-the-pipeline/)
covered OIDC, which exchanges a workflow identity for a short-lived token. It removes an
entire category of leak.

## What I took away

- **Detection is a smoke alarm, not a fire code.** Scan staged changes, the repo, and the
  full history.
- **Rotate before you rewrite.** History rewriting does not un-leak anything.
- **Move secrets out of the repo entirely.** Secret managers, SOPS, and Vault replace the
  problem; OIDC deletes it.
- **Guard the edges.** Pre-commit and push protection stop the next leak at the door.

Next up: turning your organisation's security decisions into rules a machine enforces —
policy as code.

— Yogender
