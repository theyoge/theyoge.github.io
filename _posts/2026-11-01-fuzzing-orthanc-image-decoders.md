---
layout: post
title: "Fuzzing Orthanc's Image Decoders (Medical Device Series, Part 3)"
date: 2026-11-01 12:00:00 +0530
categories: [medtech]
tags: [fuzzing, libfuzzer, asan, dicom, orthanc, pacs, cpp, security]
description: "A beginner's guide to fuzzing Orthanc, the open-source PACS: building the framework with AddressSanitizer (in Docker), writing a harness for the PAM image parser, and mapping the image-decoding attack surface."
---

In [Part 2](/writeups/fuzzing-dcmtk-libfuzzer-asan/) we fuzzed DCMTK, the parser
*library*. Now we move up a layer to **Orthanc** — the open-source PACS server that
embeds DCMTK and adds its own image processing, DICOMweb REST API, and plugins.

Orthanc is a great target because it does *more* than parse: it decodes and
re-encodes images (PNG, JPEG, a Philips-specific RLE variant, palettes), ingests
uploads over HTTP, and unpacks gzip/zip. Each of those is a hand-written parser or
buffer routine that eats attacker-controlled bytes.

This post walks through standing up an ASan + libFuzzer setup for Orthanc, the
hardest part being the build itself.

## Why the build is the hard part

DCMTK is a single library. Orthanc is a *framework* plus a *server*, and it depends
on `boost`, `jsoncpp`, `libpng`, `libjpeg`, `sqlite`, and its own bundled copy of
DCMTK. Building it with sanitizers is therefore a dependency-management exercise
first and a fuzzing exercise second. We'll use **Docker** so every dependency is
installed in one reproducible step.

## What you need

- Docker
- The Orthanc source (mirrored on GitHub from its canonical Mercurial repo)

---

## Step 1 — Get the source

The canonical Orthanc source lives in a Mercurial repo, but GitHub has a mirror:

```bash
git clone https://github.com/jodogne/OrthancMirror.git orthanc
cd orthanc
ls OrthancFramework/Sources/Images/   # PamReader, JpegReader, PngReader, ...
```

The interesting files are in `OrthancFramework/Sources/Images/`. In particular,
**`PamReader.cpp`** is the workhorse: Orthanc decodes every compressed image into a
PAM (Portable Arbitrary Map) intermediate before converting it, so the PAM parser
is on the hot path for *all* image ingest.

## Step 2 — Build the framework with ASan, in Docker

Orthanc's `CMakeLists.txt` lives under `OrthancServer/`, and with
`-DALLOW_DOWNLOADS=ON` it fetches its own pinned copies of the dependencies (DCMTK,
jsoncpp, boost) and builds them alongside the framework — which is exactly what we
want, because those dependencies then also get compiled with our sanitizer flags.

```dockerfile
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake clang ninja-build \
    libboost-all-dev libpng-dev libjpeg-dev libsqlite3-dev \
    libcurl4-openssl-dev zlib1g-dev uuid-dev libssl-dev \
    ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY orthanc /src/orthanc

RUN mkdir -p /build && cd /build && \
    CC=clang CXX=clang++ cmake /src/orthanc/OrthancServer \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g -O1" \
      -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g -O1" \
      -DSTATIC_BUILD=ON \
      -DALLOW_DOWNLOADS=ON \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 && \
    cmake --build . -j"$(nproc)"
```

Two details worth understanding:

- **`-fsanitize=fuzzer-no-link,address`** instruments the *library* with ASan, but
  does **not** link the fuzzer runtime in (that comes later, on the harness).
  If you used plain `-fsanitize=fuzzer`, the framework would fail to link because
  `main()` is missing.
- **`-DALLOW_DOWNLOADS=ON`** is the key Orthanc flag — it pins and downloads the
  exact dependency versions, avoiding version drift with whatever your distro ships.

---

## Step 3 — Write the PAM harness

Because every image goes through `PamReader`, it's the highest-leverage first
target. The harness feeds raw bytes in and lets Orthanc's own exception type catch
malformed inputs (so a "bad file" doesn't crash the fuzzer — only a *memory* bug
will):

```cpp
// fuzz_pam.cc
#include <cstdint>
#include <cstddef>
#include "Images/PamReader.h"
#include "OrthancException.h"

using namespace Orthanc;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (1u << 22)) return 0;
    const void *buf = static_cast<const void *>(data);

    // Two code paths: unaligned (wraps input) and aligned (extra malloc + copy)
    for (bool aligned : {false, true}) {
        try {
            PamReader reader(aligned);
            reader.ReadFromMemory(buf, size);
            (void)reader.GetWidth();
            (void)reader.GetHeight();
            (void)reader.GetPitch();
            (void)reader.GetConstBuffer();
        } catch (OrthancException &) {
            // expected for malformed PAM — keep fuzzing
        }
    }
    return 0;
}
```

Note the two paths: `PamReader(false)` points the accessor *into* the input buffer,
while `PamReader(true)` allocates an aligned copy. Both are worth exercising — the
byte-swap loop for 16-bit PAM behaves differently depending on alignment.

---

## Step 4 — Compile and run

```bash
clang++ -std=c++17 -fsanitize=fuzzer,address -fno-omit-frame-pointer -g -O1 \
  -I/src/orthanc/OrthancFramework/Sources \
  -I/build/Autogenerated \
  fuzz_pam.cc \
  /build/libOrthancFramework.a \
  -lboost_filesystem -lboost_thread -lboost_system -lboost_locale \
  -lz -lpng -ljpeg -lsqlite3 -lcurl -luuid -lssl -lcrypto -lpthread \
  -o fuzz_pam
```

Seed it with a few valid PAM files (a `P7` header + raw pixels — trivially easy to
generate by hand or with Python), then run:

```bash
./fuzz_pam -max_total_time=600 -jobs=4 -workers=4 -timeout=15 seeds/
```

---

## Mapping the attack surface

Beyond `PamReader`, the image-ingest paths worth targeting, in rough order of
interest:

| Path | Why it's interesting |
| --- | --- |
| Philips `PMSCT_RLE1` decompression (`DicomImageDecoder.cpp`) | custom RLE with escape/delta sequences — hand-rolled buffer logic |
| Palette color LUT (`DicomImageDecoder.cpp`) | index-into-table logic, classic OOB-read spot |
| gzip / zip metadata parsing | memory-exhaustion vectors (compression bombs) |
| `DicomStreamReader` | streaming DICOM parser, different from the file parser |
| DICOMweb STOW/JSON ingestion | HTTP layer + JSON → DICOM conversion |

The general rule holds everywhere: **the code that turns attacker bytes into
allocated buffers is where the memory bugs live**, and fuzzing is how you make the
compiler's sanitizers do the finding for you.

## Where to go next

- Wire these harnesses into **OSS-Fuzz** or a CI loop so fuzzing keeps running
  against every commit, not just locally.
- Do **variant analysis** on any crash you find — one bug usually has siblings in
  the same file.
- Report responsibly through the project's private channel and wait for the fix
  before publishing.

This closes the loop on the tooling side. In the next post we'll take a *specific*
piece of parsing code and walk through auditing it by hand — reading for the
integer-overflow and bounds-check patterns that fuzzing then confirms.
