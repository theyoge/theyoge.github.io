---
layout: post
title: "Hardening the Container: Build, Scan, and Sign Your Images"
date: 2026-10-19 12:00:00 +0530
categories: [devsecops]
tags: [devsecops, containers, docker, trivy, cosign, supply-chain]
description: "Container security from build to deploy: a minimal base image, non-root runtime, image scanning with Trivy, and signing with cosign so only trusted images run."
---

<img class="post-hero" src="/assets/img/container-hardening.svg" alt="Container hardening: minimal base image, non-root, image scanning, and signing" width="1200" height="380">

The [previous post](/writeups/sca-sbom-dependencies/) was about the dependencies you pull in. This one is about the box you ship them in: the **container image**. An image is a full filesystem — an OS, a package manager, a shell, and your app — and every one of those layers is attack surface. Hardening is the work of making that surface as small as possible, then proving the image is the one you built.

<figure class="post-figure">
  <img src="/assets/img/container-flow.svg" alt="Pipeline: Dockerfile, build, scan with Trivy, harden, sign with cosign, verify at admission" width="1200" height="260">
  <figcaption>Figure 1 — A hardened image pipeline: build small, scan, sign, verify.</figcaption>
</figure>

## Start from a smaller base

The single biggest lever is the base image. A full Debian image carries a shell, a package manager, and hundreds of packages you will never use — all potential CVEs. Options, roughly by size and surface:

| Base | Size (rough) | Trade-off |
| --- | --- | --- |
| `debian` / `ubuntu` | large | familiar, huge surface |
| `-slim` variants | medium | fewer docs/tools |
| `alpine` | small | musl libc can break native deps |
| `distroless` | tiny | no shell/package manager — harder to debug |
| `scratch` | minimal | static binaries only |

"Distroless" images contain only your app and its runtime dependencies: no shell means an attacker who lands in the container has almost nothing to pivot with. The cost is that you cannot `docker exec` a shell for debugging — often a fair trade.

## Multi-stage builds keep build tools out of the final image

Compilers, test frameworks, and dev dependencies should never ship. Split the build:

```dockerfile
# ---- build stage ----
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ---- runtime stage ----
FROM gcr.io/distroless/nodejs22-debian12
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
USER nonroot
EXPOSE 3000
CMD ["dist/server.js"]
```

Only the `runtime` stage becomes the image. The compiler, the source, and the dev dependencies are left behind.

## Run as non-root, and lock it down

A container that runs as root is a privilege-escalation waiting to happen. Defenses that cost nothing:

```dockerfile
USER nonroot              # never root
```

```yaml
# in the deployment (Kubernetes example)
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

Also: **never bake secrets into an image**. Layers are cached and inspectable; a token in a `RUN` or `ENV` is effectively published. Inject secrets at runtime.

## Pin by digest, not tag

A tag like `node:22-slim` is a moving target — it can change under you. Pin the digest for reproducibility and to make tampering detectable:

```dockerfile
FROM node:22-slim@sha256:6c1f...ab9d
```

## Scan the image

Trivy scans the whole image, both OS packages and language dependencies:

```bash
trivy image juice-shop:local
trivy image --severity HIGH,CRITICAL --exit-code 1 juice-shop:local
```

Two lessons from real scans: the majority of findings usually come from the **base OS packages**, not your app code — which is why the base image choice matters so much. And the fix is usually **rebuild on a fresher base**, not patch packages inside the image.

Wire it into CI alongside the filesystem scan:

```yaml
      - name: Scan image
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: juice-shop:local
          format: sarif
          output: image.sarif
          severity: HIGH,CRITICAL
          exit-code: "1"
```

## Sign and verify

Scanning tells you what is *in* an image. **Signing** tells you *who built it* and that it has not been tampered with. [cosign](https://github.com/sigstore/cosign) makes this practical with keyless signing backed by OIDC — no long-lived private key to leak:

```bash
cosign sign --yes ghcr.io/you/juice-shop@sha256:6c1f...ab9d

# attach the SBOM as a signed attestation
cosign attest --yes --predicate sbom.cdx.json --type cyclonedx ghcr.io/you/juice-shop@sha256:6c1f...ab9d
```

Then **verify before running** — at deploy time or at admission control (Kyverno, OPA Gatekeeper):

```bash
cosign verify ghcr.io/you/juice-shop@sha256:6c1f...ab9d \
  --certificate-identity-regexp='^https://github.com/you/.+' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

The payoff: "only images signed by our CI may run in the cluster" becomes an enforceable rule, not a hope. That closes the loop between the [CI post](/writeups/devsecops-in-ci/) and the running system.

## What I took away

- **An image is a filesystem, and every file is surface.** Shrink the base and drop the build tools.
- **Root is not a default you accept.** Non-root, no privilege escalation, dropped capabilities.
- **Scan, then fix by rebuilding** on a patched base — usually the root cause.
- **Trust is provable.** Signing and verification turn "we think it's ours" into a cryptographic yes.

Next up: the layer *under* the app — infrastructure as code, and the misconfigurations that create holes before any code runs.

— Yogender
