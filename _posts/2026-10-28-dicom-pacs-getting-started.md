---
layout: post
title: "DICOM & PACS Security: Getting Started (Medical Device Series, Part 1)"
date: 2026-10-28 12:00:00 +0530
categories: [medtech]
tags: [dicom, pacs, medical-device, pentesting, embedded, offensive-security, phil]
description: "The first post in a series on hacking medical devices: what DICOM/PACS is, why it is insecure by design, and a hands-on lab to enumerate patients, inject images, and start hunting for real bugs."
---

Every hospital runs on DICOM. Every CT, MRI, X-ray, and ultrasound machine speaks it, and
they all ship their images to a PACS — a server that stores and serves those scans. It is
one of the most deployed, least-secured protocol stacks in the world, and it is the exact
attack surface that embedded/product-security roles at medical-device companies (Stryker,
Philips, GE, Abbott) pay for.

This is the first post in a series on **medical-device security**. We start with the
software/protocol layer — DICOM and PACS — because you can learn it entirely in Docker,
it maps directly to real job requirements ("protocol endpoints", "vulnerability
analysis"), and the bug classes are the same ones fuzzing tools find every day.

## New to DICOM? A 30-second primer

- **DICOM** (Digital Imaging and Communications in Medicine, ISO 12052) is both a *file
  format* and a *network protocol* for medical images.
- **PACS** (Picture Archiving and Communication System) is the archive that stores and
  serves those images.

Devices talk to the PACS using **DIMSE** services. These are the four that matter to an
attacker:

| Service | What it does | Offensive use |
| --- | --- | --- |
| C-ECHO | "Are you alive?" | Recon, fingerprinting |
| C-FIND | Query the archive | Enumerate patients (PHI exfil) |
| C-STORE | Send an image | Inject images / malformed files |
| C-MOVE / C-GET | Retrieve images | Bounce attacks, data theft |

## Why it is insecure by design

Three properties make DICOM a gift to attackers:

1. **No mandatory authentication.** A device that can reach the PACS on the right port
   can usually query it. Patient names, IDs, birth dates — over an empty C-FIND.
2. **No mandatory encryption.** DICOM traffic is cleartext. Fire up Wireshark and PHI
   scrolls by in plaintext.
3. **It assumes a trusted network.** Old deployments treat "it's on the hospital LAN" as
   a security boundary. Researchers routinely find thousands of PACS servers exposed
   directly on the internet.

None of this is hypothetical — [recent
research](https://www.ioactive.com/penetration-testing-of-the-dicom-protocol-real-world-attacks/)
and CVEs like DCMTK's path-traversal file-write keep proving it.

## The lab

Everything below runs against a local, deliberately-open PACS I built for this series:

```
https://github.com/theyoge/dicom-lab
```

It ships an Orthanc PACS (the most popular open-source PACS) with authentication
*disabled* and C-FIND/C-MOVE/C-GET *allowed from unknown devices* — on purpose, so you
can see the insecure-by-default behavior first-hand. A stock Orthanc would reject most of
this, which is exactly the lesson.

### 1. Bring it up

```bash
git clone https://github.com/theyoge/dicom-lab
cd dicom-lab
docker compose up -d --build
```

This starts a `pacs` (port 4242 = DIMSE, 8042 = web UI) and a `client` with DCMTK and
`pynetdicom` pre-installed.

### 2. Generate fake patients

```bash
docker compose exec client python 00_generate_samples.py /images
```

Three synthetic CT studies, each carrying PHI (name, ID, sex, birth date).

### 3. C-ECHO — is it alive?

```bash
docker compose exec client python 01_c_echo.py pacs 4242
# [+] C-ECHO response: 0x0000 (Success)
```

### 4. C-STORE — inject the images

```bash
for f in P0001 P0002 P0003; do
  docker compose exec client python 03_c_store.py /images/$f.dcm pacs 4242
done
```

### 5. C-FIND — dump every patient, no credentials

```bash
docker compose exec client python 02_c_find_enum.py pacs 4242
```

```
    DOE^JOHN         ID=P0001  sex=M  dob=19750312
    ROE^JANE         ID=P0002  sex=F  dob=19881104
    SMITH^ALICE      ID=P0003  sex=F  dob=19650220
[+] 3 patient record(s) returned. No credentials were needed.
```

That last line is the whole point. An empty patient-level query returned every record in
the archive. The Python is about 30 lines — nothing clever, just the protocol doing what
it was designed to do.

### 6. Watch it in the clear

```bash
tshark -i any -f "tcp port 4242"
```

Re-run the C-FIND and watch the patient data cross the wire unencrypted.

## What we are attacking

| Surface | Attack |
| --- | --- |
| C-FIND / C-GET | Unauthenticated patient enumeration |
| C-STORE | Upload malicious or malformed images (parser bugs, stored-XSS in viewers) |
| C-MOVE | Bounce attack — redirect data to an attacker-controlled AE |
| DICOMweb (REST, port 8042) | QIDO/WADO/STOW endpoints, path traversal, IDOR |
| The file parser | Buffer overflows / path traversal in DCMTK and Orthanc |

## Where this series goes

1. The DICOM file format — preamble, `DICM` magic, and `(group,element) VR length value`
   elements, parsed by hand.
2. Attacking the DICOMweb REST API.
3. Fuzzing DCMTK and Orthanc with AddressSanitizer, hunting for real CVEs.
4. Then down the stack: firmware extraction and UART/JTAG, the hardware layer medical
   devices actually ship on.

The end goal is not just to understand the protocol — it is to find and responsibly
report real vulnerabilities in the software hospitals run on. If that sounds interesting,
clone the lab and follow along.
