---
layout: post
title: "Infrastructure as Code, Scanned: Catch Misconfigs Before terraform apply"
date: 2026-10-20 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, iac, terraform, kubernetes, trivy, misconfig]
description: "Scan Terraform and Kubernetes before they ship: the misconfigurations that create real holes, how to read the findings, and how to suppress responsibly."
---

<img class="post-hero" src="/assets/img/iac-scanning.svg" alt="Infrastructure as code scanning: Terraform, Kubernetes, findings, and a PR gate" width="1200" height="380">

We have covered your source code, your dependencies, and your container image. There is one more thing that becomes the production environment: **infrastructure as code**. Terraform and Kubernetes YAML create networks, buckets, and workloads — which means a misconfiguration there is not a code smell, it is a vulnerability you can exploit before a single line of application code runs.

<figure class="post-figure">
  <img src="/assets/img/iac-flow.svg" alt="IaC workflow: write IaC, scan with trivy config, review findings, fix, then plan or apply" width="1200" height="260">
  <figcaption>Figure 1 — Scan the code that builds your infrastructure, before it is applied.</figcaption>
</figure>

## Why IaC is security-critical

Infrastructure as code is declarative and version-controlled — the same properties that make it a great shift-left target. A mistake is a diff you can see in a pull request, and a scanner can read it before `terraform apply` ever touches a cloud account.

The misconfigurations that matter are mundane and repeatable:

- **Storage**: publicly readable S3 / GCS buckets.
- **Network**: security groups open to `0.0.0.0/0`, unrestricted ingress.
- **Identity**: IAM policies with `Action: "*"` or `Resource: "*"`.
- **Kubernetes**: `privileged: true`, `runAsUser: 0`, missing resource limits, hostPath mounts.
- **Encryption**: databases and disks created unencrypted by default.

None of these are exotic bugs. They are defaults people forgot to override, and each one has caused real breaches.

## The tools

| Tool | Focus |
| --- | --- |
| `trivy config` | Terraform, Kubernetes, Dockerfile, CloudFormation |
| `checkov` | Broad multi-cloud IaC coverage, rich policies |
| `tfsec` | Terraform-specific (now part of Trivy) |
| `kics` | Many IaC types, query-based |

Because you already have Trivy from earlier posts, `trivy config` is the least friction. Scan the infrastructure directory:

```bash
# Terraform
trivy config ./infrastructure/terraform

# Kubernetes manifests
trivy config ./k8s

# everything under a path, highest severity failing
trivy config --severity HIGH,CRITICAL --exit-code 1 .
```

The Juice Shop repository is a lovely lab for this: it ships an **intentionally insecure** `infrastructure/` and `infrastructure/terraform/` folder. Point Trivy at it and you will get findings that are genuinely exploitable — which is the whole point of practicing on it.

## Reading a finding

A Trivy config finding gives you the misconfiguration ID, the file and line, the severity, and a description. The skill is translating it into impact. "Security group allows ingress from 0.0.0.0/0 on port 22" is not a lint error — it is SSH exposed to the internet. Read each one as an attacker would: *what does this let someone reach?*

## Suppressing without going blind

Some findings are genuinely acceptable in a given context — a bucket that is *meant* to be public, a privileged pod that is a node agent. Suppress narrowly and with a record:

```bash
# a specific, reviewed exception
# .trivyignore
AVD-AWS-0086   # public bucket: intentional, static website hosting
```

Trivy also supports inline skips (`#trivy:ignore:AVD-AWS-0086`) directly above the resource. The rule: one finding per exception, with a reason, reviewed like code. A blanket `--skip-policy` or disabling a whole category is how IaC scanning quietly stops working.

## Wiring into CI

Add a config scan to the workflow from the [CI post](/writeups/devsecops-in-ci/):

```yaml
      - name: Scan IaC
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: ./infrastructure
          severity: HIGH,CRITICAL
          format: sarif
          output: iac.sarif
          exit-code: "1"
```

Combined with branch protection, this means a pull request that opens a security group to the world **cannot merge** until someone fixes it or documents why.

## The next level: policy as code

Config scanning catches *known bad patterns*. The layer above it is **policy as code** — rules that encode *your* organisation's decisions ("no public buckets, ever", "every workload must set resource limits") using OPA/Conftest or Kyverno. That belongs to a later post in this series, but the mental model is the same: a misconfiguration is a policy violation, caught as early as possible.

## What I took away

- **Infrastructure is code, so scan it like code.** The diff is the attack surface.
- **The findings are boring and that is the point.** Defaults cause breaches.
- **Suppress narrowly and with reasons.** A muted scanner is worse than no scanner.
- **Scan before apply.** CI on the pull request is where the gate belongs.

Next up: the last layer — testing the running application itself with DAST, where SAST and scanners cannot see.

— Yogender
