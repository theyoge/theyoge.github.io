---
layout: post
title: "Policy as Code: Turning Decisions into Enforceable Rules"
date: 2026-10-26 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, policy-as-code, opa, rego, conftest, kyverno]
description: "Scanners catch known-bad patterns; policy as code enforces your organisation's decisions. Write, test, audit and enforce rules with OPA/Rego, Conftest and Kyverno."
---

<img class="post-hero" src="/assets/img/policy-as-code.svg" alt="Policy as code: decisions encoded, tested, and enforced at the PR and at admission" width="1200" height="380">

Scanners like the ones in the [IaC post](/writeups/iac-scanning/) find *known* bad
patterns. But your organisation has opinions a scanner does not know: "we never deploy a
public bucket", "every workload must set resource limits", "images must come from our
registry". **Policy as code** turns those opinions into rules a machine enforces
automatically, at the exact moment a decision is made.

## What policy as code is

A policy is a small program that reads a **decision** (a Terraform plan, a Kubernetes
manifest, a pull request) and answers **allow** or **deny**, with a reason. Because it is
code, it can be versioned, reviewed, tested, and run in CI — the same properties that make
everything else in this series work.

The key idea: policy is not a document nobody reads; it is a check that actually runs.

<figure class="post-figure">
  <img src="/assets/img/policy-flow.svg" alt="Policy lifecycle: decide the rule, encode it in Rego or YAML, test it against fixtures, run in audit mode, then enforce" width="1200" height="260">
  <figcaption>Figure 1 — The policy lifecycle: decide, encode, test, audit, enforce.</figcaption>
</figure>

## Where policy runs

Two natural enforcement points:

- **In the pull request** — before a misconfiguration is merged (Conftest on IaC).
- **At admission** — before a workload is allowed to start (Kyverno / OPA Gatekeeper in
  Kubernetes).

Same idea, different moment. Catch it as early as you can, and keep a runtime gate for
anything that bypasses the first.

## OPA and Rego in one minute

**OPA** (Open Policy Agent) is the engine; **Rego** is its language. A rule is a `deny`
with a message, and it "fires" when the body is true:

```rego
package main

deny[msg] {
  bucket := input.resource.aws_s3_bucket[name]
  bucket.acl == "public-read"
  msg := sprintf("S3 bucket %q must not be public-read", [name])
}
```

Read it as: *if there is a bucket whose ACL is `public-read`, produce a denial.* Nothing
more to it than that.

## Conftest for infrastructure as code

[Conftest](https://www.conftest.dev) runs Rego against parsed config (Terraform, YAML,
JSON, and more):

```bash
conftest test ./infrastructure/terraform
```

Put policies in a `policy/` directory, and **test them with fixtures** so a bad rule does
not ship:

```bash
conftest test --policy policy/ --namespace main fixtures/public-bucket.tf
# expect: FAIL — S3 bucket "assets" must not be public-read
```

Testing policies against known inputs is what makes them trustworthy: you prove the rule
blocks what it should and allows what it should not.

## Kyverno for Kubernetes

[Kyverno](https://kyverno.io) expresses Kubernetes policy in YAML — no Rego required:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-pinned-image
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Image tag 'latest' is not allowed; pin a version or digest."
        pattern:
          spec:
            containers:
              - image: "!*:latest"
```

`validationFailureAction` is the important switch: `Audit` reports violations, `Enforce`
blocks the workload.

## Writing policy people will not hate

- **Fail closed, explain clearly.** A denial should say what to change, not just "denied".
- **Start in audit mode.** Run `Audit` (or warn-only in CI) first, so you see what would
  break before you break it.
- **Give every exemption an owner and an expiry.** A permanent exception is a silent
  policy change.
- **Test the rules like code.** Fixtures in CI, reviewed in pull requests.

## Rollout: warn, then enforce

The failure mode of policy as code is turning everything to `Enforce` on day one and
freezing the team. The sequence that works: encode the rule, test it, run it in **audit**
mode until the backlog is clear, then flip to enforce. That is the same "don't become the
blocker" lesson from the whole series — a gate exists to make shipping safer, not slower.

## What I took away

- **Scanners know patterns; policy knows your intent.** Encode the decisions.
- **Two enforcement points.** The pull request and admission control.
- **Test policies or distrust them.** Fixtures in CI, like any other code.
- **Audit first, enforce second.** Adoption is part of the design.

Next up: making sense of everything all these tools produce — triage at scale.

— Yogender
