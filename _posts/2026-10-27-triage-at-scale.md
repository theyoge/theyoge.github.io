---
layout: post
title: "Triage at Scale: One Queue from Many Scanners"
date: 2026-10-27 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, triage, sarif, sbom, vex, epss]
description: "Seven scanners produce thousands of findings. Here is how to collapse them into one deduplicated, prioritized, routed queue — and stop alert fatigue."
---

<img class="post-hero" src="/assets/img/triage-scale.svg" alt="Triage: collect SARIF, dedupe by root cause, prioritize with KEV and EPSS, and route with owners and SLAs" width="1200" height="380">

The tools in this series each work. Run them all and you get a different problem: seven
dashboards, thousands of findings, and a team that stops looking. The final skill of a
security engineer is not running scanners — it is **collapsing their output into one
queue a human can actually work**. That is triage at scale.

## The problem, plainly

- Every tool has its own UI and its own severity scheme.
- The same issue appears in several tools (SAST suspects, DAST confirms).
- Raw counts are dominated by noise, so the signal is invisible.
- Nobody owns the findings, so they rot.

The goal is the opposite of a dashboard: **one deduplicated, prioritized, owner-assigned
list**, where every item is action-shaped.

<figure class="post-figure">
  <img src="/assets/img/triage-flow.svg" alt="Triage pipeline: collect all tools as SARIF, dedupe by root cause, prioritize with KEV, EPSS and CVSS, route to owners with SLAs, and auto-close when fixed" width="1200" height="260">
  <figcaption>Figure 1 — From noise to a queue: collect, dedupe, prioritize, route, auto-close.</figcaption>
</figure>

## Step 1 — Collect: make every tool speak SARIF

You met **SARIF** in the [CI post](/writeups/devsecops-in-ci/); here it earns its keep as
the common language. Almost every scanner can emit it, and GitHub code scanning can ingest
it for free:

```bash
semgrep --sarif --output semgrep.sarif
trivy fs --format sarif --output trivy.sarif .
```

Collect them all into one place — GitHub code scanning for a start, or a system like
DefectDojo when you outgrow it. The point is a single ingestion path, not seven tabs.

## Step 2 — Dedupe: find the root cause

The same bug arrives many times. Collapse duplicates by what actually identifies them:

- **CVE + package + version** for dependency findings (the same CVE via three paths is one
  fix).
- **Rule + file + line** for SAST findings.
- **Fingerprints** — most SARIF results carry a stable partial fingerprint you can group on.

One row per fix, not one row per report.

## Step 3 — Prioritize: not all findings are equal

Sort by **likelihood of being exploited**, not by raw severity. The order that works:

1. **CISA KEV** — known to be exploited in the wild. Fix now.
2. **EPSS** — the probability of exploitation in the next 30 days.
3. **CVSS** — the base severity, as a tiebreaker.

Then fold in context: **reachability** (is the vulnerable code path used?), **asset
criticality** (customer data vs a sandbox), and **fix availability** (is there a patched
version yet?). A medium in a reachable auth path outranks a critical in dead code — and
being able to say *that* out loud is the whole skill.

## Step 4 — Route: owners and SLAs

A finding without an owner is not a finding. Assign each to the squad that owns the code,
with an **SLA by severity** (critical in days, not quarters), and track it where they
already work — the issue tracker, not a security-only tool. The [agent post](/writeups/security-agents-claude-agent-sdk-mcp/)
showed a way to do the first pass and the [code review](/writeups/devsecops-in-ci/)
annotations are where developers actually see it.

## Step 5 — Auto-close and reduce

- **Auto-close on fix.** Code scanning and most platforms close findings when the code
  changes, so the queue reflects reality.
- **Fix classes, not instances.** One Semgrep rule or one lint removes a hundred findings,
  permanently.
- **Record "not affected" as data.** **VEX** is the machine-readable "this finding does
  not apply to us, and here is why" — so it stops reappearing and reads as a decision, not
  a mute.
- **Tune, do not disable.** Tighten allowlists and severity gates (as in the [SCA](/writeups/sca-sbom-dependencies/)
  and [secrets](/writeups/secrets-detection-to-prevention/) posts) instead of switching a
  scanner off.

## The metrics that matter

- **Mean time to remediate**, by severity — is the queue actually draining?
- **False-positive rate** per tool — is the noise getting better or worse?
- **Backlog trend** — are we fixing faster than we accumulate?

Avoid "total findings" as a success measure; it rewards either not looking or hiding.

## Pulling it together

This is where the whole series connects. Your scanners feed SARIF; your policies decide
what is allowed; your agent does the first pass; and you keep **one** ranked queue with
owners and SLAs. The engineer's time goes to the judgment calls — is it exploitable, what
is the real fix, what do we accept — because that is the only part a machine cannot do for
you.

## What I took away

- **The output is the product.** Seven dashboards is not a security program; one queue is.
- **Dedupe by root cause, prioritize by exploitability.** KEV and EPSS over raw CVSS.
- **Every finding needs an owner and an SLA**, or it is already forgotten.
- **Reduce classes, record exceptions, and measure the trend** — not the raw count.

That closes the loop this series opened: build the gate, take it everywhere, secure the
pipeline, encode the policy, and turn it all into one queue a person can act on.

— Yogender
