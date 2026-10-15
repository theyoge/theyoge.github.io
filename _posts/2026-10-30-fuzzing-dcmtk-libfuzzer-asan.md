---
layout: post
title: "Fuzzing DCMTK: Finding Memory Bugs in the DICOM Parser (Medical Device Series, Part 2)"
date: 2026-10-30 12:00:00 +0530
categories: [medtech]
tags: [fuzzing, libfuzzer, asan, dicom, dcmtk, cpp, security]
description: "A beginner's guide to setting up libFuzzer + AddressSanitizer against DCMTK: build with sanitizers, write a fuzz harness, build a seed corpus, run the fuzzer, and read the crashes."
---

This post is about *how* to fuzz a C/C++ codebase, using DCMTK — the C++ library
behind almost every DICOM parser on the planet — as the target. If you followed
[Part 1](/writeups/dicom-pacs-getting-started/), you know *what* DICOM is. Now we
learn how to find bugs in the software that parses it.

No prior fuzzing experience is assumed. By the end you'll have a working setup and
know what every piece does.

## The two tools: a 30-second primer

- **Fuzzing** throws millions of mutated inputs at a program and watches for a
  crash. The input that crashes is saved so you can replay it.
- **AddressSanitizer (ASan)** instruments the program so that memory bugs — buffer
  overflows, use-after-free, out-of-bounds reads — are detected *immediately*, with
  a stack trace, instead of silently corrupting memory.

`libFuzzer` is the fuzzer that ships **inside clang**. You don't install it
separately — you just compile with `-fsanitize=fuzzer`. Combining it with ASan is
one extra flag: `-fsanitize=fuzzer,address`.

## Why DCMTK

DCMTK (`dcmtk`) is the reference DICOM implementation — it's bundled into Orthanc,
many PACS servers, and countless medical-device firmware images. It parses
attacker-controlled input (a DICOM file or a C-STORE over the network), which makes
it a textbook fuzzing target. It's also real: DCMTK 3.7.0 had a cluster of
memory-safety CVEs fixed in 3.7.1, so the bug *classes* are real even if the
current head is well-hardened.

## What you need

- `clang` (any recent version — check `clang --version`)
- `cmake` and `make`
- A few GB of disk and a few CPU cores

Everything below was tested on clang 21 and DCMTK 3.7.1.

---

## Step 1 — Build DCMTK with ASan

Get the source and configure a build directory that compiles everything with the
sanitizer flags:

```bash
git clone https://github.com/DCMTK/dcmtk.git
cd dcmtk && mkdir build-asan && cd build-asan

CC=clang CXX=clang++ cmake .. \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DBUILD_SHARED_LIBS=OFF \
  -DDCMTK_WITH_OPENSSL=OFF \
  -DDCMTK_WITH_ZLIB=ON \
  -DDCMTK_WITH_ICONV=OFF \
  -DBUILD_APPS=OFF

make -j8 ofstd oflog dcmdata
```

What each flag does:

| Flag | Meaning |
| --- | --- |
| `-fsanitize=address` | enable ASan |
| `-fno-omit-frame-pointer` | keep stack frames so ASan reports are readable |
| `-g -O1` | debug info + light optimization (fast, still debuggable) |
| `-DBUILD_SHARED_LIBS=OFF` | static libs, so the fuzzer links cleanly |
| `-DBUILD_APPS=OFF` | skip the CLI tools; we only need the libraries |

We build just three libraries (`ofstd`, `oflog`, `dcmdata`) because the harness
only needs the core parser. You'll extend this to the image codecs later.

---

## Step 2 — Write the fuzz harness

A harness is a single function, `LLVMFuzzerTestOneInput`, that libFuzzer calls with
one mutated input. Yours must turn those bytes into DICOM parsing calls:

```cpp
// fuzz_dcm.cc
#include <cstdint>
#include <cstddef>
#include "dcmtk/dcmdata/dctk.h"
#include "dcmtk/dcmdata/dcistrmb.h"

// Walk every element and stringify it, so the parser actually does work
static void deep_iterate(DcmObject *obj) {
    if (!obj) return;
    DcmObject *child = NULL;
    while ((child = obj->nextInContainer(child)) != NULL) {
        DcmElement *el = dynamic_cast<DcmElement *>(child);
        if (el) {
            OFString s;
            el->getOFString(s, 0);            // stringify (exercises VR handling)
            if (el->getVR() == EVR_SQ) deep_iterate(el);  // recurse into sequences
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (1u << 20)) return 0;  // keep iterations fast

    // Parse DICOM straight from a memory buffer (no file I/O)
    DcmInputBufferStream buf;
    buf.setBuffer(const_cast<void *>(static_cast<const void *>(data)),
                  static_cast<offile_off_t>(size));
    buf.setEos();

    DcmFileFormat dfile;
    OFCondition cond = dfile.read(buf, EXS_Unknown, EGL_noChange, DCM_MaxReadLength);
    if (cond.good()) {
        deep_iterate(dfile.getDataset());
    }
    return 0;
}
```

Key points for a beginner:

- **`return 0`** means "input processed". A crash or a sanitizer report is what
  makes libFuzzer save the input.
- **`size > (1u << 20)`** caps inputs at 1 MB so a single iteration can't eat
  your whole day.
- **`DcmInputBufferStream`** parses from memory instead of a file — essential, so
  fuzzing isn't bottlenecked on disk I/O.
- The `deep_iterate` function matters: parsing alone often doesn't *touch* the
  value, so we force DCMTK to stringify and descend into every element.

---

## Step 3 — Compile the harness

```bash
clang++ -std=c++17 -fsanitize=fuzzer,address -fno-omit-frame-pointer -g -O1 \
  -Idcmtk/dcmdata/include -Idcmtk/ofstd/include -Idcmtk/oflog/include \
  -Idcmtk/build-asan/config/include \
  fuzz_dcm.cc \
  build-asan/lib/libdcmdata.a build-asan/lib/liboflog.a \
  build-asan/lib/libofstd.a build-asan/lib/liboficonv.a \
  -lz -lpthread -o dcm_fuzzer
```

Notice `-fsanitize=fuzzer,address` — that's libFuzzer + ASan together. The include
paths point at the *source* headers; `build-asan/config/include` holds the
generated `osconfig.h`.

---

## Step 4 — Build a seed corpus

libFuzzer starts from *valid* inputs and mutates them. Garbage in means it spends
forever rediscovering basic structure. You want a handful of small, valid DICOMs:

1. **Generate a few valid files** with Python (`pip install pydicom`) or any tool
   that writes DICOM — a couple of CT/MR files, an RGB secondary capture, a
   structured report.
2. **Grab a ready-made corpus.** The
   [`pwnlabmx/dicom-fuzzing-corpus`](https://github.com/pwnlabmx/dicom-fuzzing-corpus)
   contains thousands of *malformed* DICOMs purpose-built to stress parsers —
   perfect both as seeds and as a one-shot regression set.

```bash
git clone https://github.com/pwnlabmx/dicom-fuzzing-corpus.git
mkdir corpus_seeds && cp your_valid_files/*.dcm corpus_seeds/
```

Rule of thumb: **fewer, valid, small seeds beat thousands of random bytes.**

---

## Step 5 — Run it and read the output

```bash
./dcm_fuzzer -max_total_time=300 -jobs=4 -workers=4 -timeout=15 corpus_seeds
```

What you'll see:

- `INFO: Loaded N modules` — sanity check.
- `#N NEW ... cov: X` — libFuzzer found a new code path (coverage grew).
- `pulse` lines — periodic progress.
- `ERROR: AddressSanitizer: heap-buffer-overflow ...` — **you found a bug**, and
  the input is saved to a file like `crash-<hash>`.

That last one is the entire point. Copy the crashing input, replay it:

```bash
./dcm_fuzzer crash-<hash>
```

and you'll get the full ASan stack trace pointing at the exact line that
overflowed.

---

## Step 6 — Go deeper: the image codecs

The parser is a good warm-up, but the *image decoding* paths (RLE, JPEG, JPEG-LS)
are where the nastier bugs live, because they do raw buffer arithmetic on pixel
dimensions. Build the extra modules and register the decoders:

```bash
make -j8 dcmimgle dcmimage dcmjpls dcmjpeg   # needs libijg8/12/16 + libdcmtkcharls
```

Then write a second harness that *decompresses* instead of just parsing:

```cpp
#include "dcmtk/dcmdata/dcrledrg.h"   // RLE decoder
#include "dcmtk/dcmjpls/djdecode.h"   // JPEG-LS decoder
#include "dcmtk/dcmjpeg/djdecode.h"   // JPEG decoder

struct Init { Init() {
    DcmRLEDecoderRegistration::registerCodecs();
    DJLSDecoderRegistration::registerCodecs();
    DJDecoderRegistration::registerCodecs();
}} init;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // ... read into DcmFileFormat as before ...
    E_TransferSyntax xfer = ds->getOriginalXfer();
    if (!DcmXfer(xfer).isEncapsulated()) return 0;     // only compressed images
    if (ds->chooseRepresentation(EXS_LittleEndianExplicit, NULL).good()) {
        DcmElement *px = NULL;
        if (ds->findAndGetElement(DCM_PixelData, px).good() && px) {
            Uint8 *ptr = NULL;
            px->getUint8Array(ptr);                    // force full decode
        }
    }
    return 0;
}
```

Seed it with **compressed** DICOMs (RLE `1.2.840.10008.1.2.5`, JPEG-LS
`1.2.840.10008.1.2.4.80`, JPEG `1.2.840.10008.1.2.4.70`) — generate them with
DCMTK's own encoders, or find sample files online.

---

## Where to go next

- **Triage every crash.** Is it a real bug or a sanitizer artifact? Is the input
  reachable from an attacker (network C-STORE) or only from a trusted local file?
- **Variant analysis.** Once you find one bug, search the codebase for the same
  pattern elsewhere (Trail of Bits' [`variant-analysis`](https://github.com/trailofbits/skills)
  skill is built for exactly this).
- **Report responsibly.** For DCMTK, send findings to `bugs@dcmtk.org` — never
  post a vulnerability publicly before the maintainers fix it.

In [Part 3](/writeups/fuzzing-orthanc-image-decoders/) we apply the same method to
Orthanc, the PACS server that embeds DCMTK — a bigger build, but a richer target.
