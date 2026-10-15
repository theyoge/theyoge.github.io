---
layout: post
title: "Your Dependencies Are Your Attack Surface: SCA, SBOMs, and Knowing What Matters"
date: 2026-10-18 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, sca, sbom, trivy, dependencies, supply-chain]
description: "Software composition analysis in depth: inventory your dependencies, generate an SBOM, match against known CVEs, and triage what actually matters."
---

<img class="post-hero" src="/assets/img/sca-sbom.svg" alt="Dependency scanning: lockfiles, CVE database, SBOM, and triage" width="1200" height="380">

So far this series has covered the code *you* write: secrets in [the first post](/writeups/shift-left-devsecops-lab/), static analysis of your source, and running it all in [CI](/writeups/devsecops-in-ci/). But a modern application is mostly code you did **not** write. Pull in Express, Sequelize, and Angular, and the vast majority of what ships is someone else's package — with its own bugs and its own CVEs. That is why **SCA** deserves its own post.

## What SCA actually is

Software Composition Analysis answers two questions:

1. **What do I depend on?** (an inventory)
2. **Which of those things have known vulnerabilities?** (a match against a database)

The first half is a **SBOM** — a software bill of materials. The second half is vulnerability matching. Tools like Trivy and `osv-scanner` do both.

<figure class="post-figure">
  <img src="/assets/img/sca-flow.svg" alt="SCA workflow: lockfiles, inventory via SBOM, match against a CVE database, prioritize, remediate" width="1200" height="260">
  <figcaption>Figure 1 — The dependency scan loop: inventory, match, prioritize, fix.</figcaption>
</figure>

## Step 1 — Inventory: the SBOM

A **Software Bill of Materials** is a machine-readable list of every component in your software, like an ingredients label. The two common formats are **SPDX** and **CycloneDX**. You generate one with a tool, not by hand.

Generate an SBOM with [Syft](https://github.com/anchore/syft):

```bash
# install
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# generate from the filesystem, in CycloneDX and SPDX formats
syft dir:. -o cyclonedx-json=sbom.cdx.json
syft dir:. -o spdx-json=sbom.spdx.json
```

An SBOM matters because it is the *inventory* everything else depends on. When the next Log4Shell drops, the question "are we affected?" is answerable in seconds if you have SBOMs, and a multi-day scramble if you do not. It is also increasingly a compliance requirement.

## Step 2 — Match: find the CVEs

Now match that inventory against a vulnerability database. Trivy pulls an advisory DB and does this for you:

```bash
# scan the repo's dependencies (and optionally secrets + misconfig)
trivy fs --scanners vuln --severity HIGH,CRITICAL .

# machine-readable output for tooling
trivy fs --format json -o trivy.json .
```

`osv-scanner` is a good alternative that queries the OSV database directly:

```bash
osv-scanner --lockfile package-lock.json
```

Under the hood, matching is version-range arithmetic: a CVE names an affected range (say `>=4.0.0, <4.17.21`), and the tool checks whether the version in your lockfile falls inside it. This is exactly why **lockfiles matter** — if you do not commit them, there is nothing precise to match against.

## Step 3 — Why "0 vulns" can be wrong and "40 vulns" can be fine

Raw counts lie. Two failure modes dominate:

- **False negatives.** A CVE may have no entry for your exact version, or the ecosystem's advisory data lags. "No findings" means "nothing *known*", not "safe".
- **False positives.** A finding in a dev-only dependency is not reachable in production. A vulnerable function that your code never calls is, in practice, not exploitable. And a CVE without a fix is not actionable today.

So the real skill is not scanning — it is **triage**.

## Prioritization: stop treating every CVE the same

Three signals, in increasing order of usefulness:

- **CVSS** — the base severity score most scanners show. Useful for a first cut.
- **EPSS** — the probability the vulnerability will actually be exploited in the wild in the next 30 days.
- **CISA KEV** — the catalog of vulns known to be exploited *right now*. If something is on KEV, it jumps the queue immediately.

The habit: sort by **KEV → EPSS → CVSS**, then factor in reachability (is the vulnerable code path even used?) and whether a fix exists.

## Remediation playbook

When a finding is real, in rough order of preference:

1. **Upgrade** the dependency to a fixed version. This is the normal path.
2. **Override / pin** a transitive dependency when the direct parent has not caught up (`npm overrides`, Maven `<dependencyManagement>`).
3. **Patch or replace** the library if no fix exists.
4. **Mitigate** — disable the vulnerable feature, add a WAF rule, restrict access.
5. **Accept with a record** — a documented exception (this is what **VEX** is for: a machine-readable "not affected / will not fix" statement). Never a silent ignore.

## Wiring it into the pipeline

You already have the Trivy step in CI from the [CI post](/writeups/devsecops-in-ci/). Extend it to also produce an SBOM as a build artifact:

```yaml
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cdx.json
```

Now every release has an inventory attached, and "are we affected by CVE-X?" is a grep away. Add **Dependabot** or **Renovate** to open upgrade PRs automatically, so remediation is continuous rather than a quarterly project.

## What I took away

- **Most of your attack surface is code you did not write.** SCA is how you see it.
- **An SBOM is the foundation.** You cannot match what you have not inventoried.
- **The scanner is easy; the triage is the job.** KEV, EPSS, reachability, and fix availability decide what is real.
- **Automate the boring part.** Continuous dependency updates beat a heroic remediation sprint.

Next up: the artifact your dependencies ship inside — the container image, and how to build one that is smaller and harder to exploit.

— Yogender
