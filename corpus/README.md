# The evaluation corpus

Every sample here is **built, not collected**. Nothing in this directory came
from the wild, from a malware feed, or from someone else's installer.

That is a deliberate trade. A collected corpus would be more representative and
its ground truth would be somebody's reverse-engineering opinion; a built corpus
is less representative and its ground truth is *exact by construction* — we
wrote the C, so we know what is in the binary. For a tool whose entire pitch is
honest measurement, exact labels are worth more than realistic ones, and the
report says so out loud in its own limitations section.

## Building it

```console
$ winget install zig.zig          # or your package manager, or ziglang.org
$ python -m corpus.build
104 binaries built, 0 failed
$ python -m eval.run --print
```

`zig cc` and nothing else. Zig cross-compiles to both Windows targets from any
host, so the corpus builds identically on a Linux CI runner and on a Windows
laptop — a corpus that only builds in one place is a corpus nobody re-runs.

`corpus/build/` is generated and gitignored. The sources are the artefact.

## What is in here

| Path | |
|---|---|
| `src/*.c` | 26 samples. One file, one claim, comment explaining what it proves |
| `material/` | A throwaway certificate and key, baked into the embedded-material samples. **The private key is public — see that directory's README** |
| `labels.toml` | Ground truth. Read this before reading any number in `eval/report.md` |
| `build.py` | Compiles every source at x86/x64 × -O0/-O2 |

Four kinds of sample:

- **positive** — the cryptography is there and we expect to find it.
- **negative** — no cryptography. Anything reported is a false positive by
  construction, including whatever the C runtime drags in.
- **defeat** — the cryptography is genuinely there and we genuinely miss it.
  These have real `truth` and empty `expect`, they drag the headline recall
  down, and that is exactly what they are for. See [`../LIMITATIONS.md`](../LIMITATIONS.md).
- **toolchain** — not a sample kind but a labelled fact: `labels.toml` records
  cryptography the compiler links in on its own. Zig's runtime puts ChaCha20 in
  every x86_64 debug build, which none of these programs asked for. The tool
  reports it, correctly, and that is the argument for binary-level CBOMs in one
  line.

## Writing a new sample

1. One `.c` file in `src/`, with a header comment saying what it proves and how
   we expect the tool to behave on it. `#include "_sink.h"` and feed results
   through `sink()` — otherwise `-O2` deletes the thing under test, which has
   happened twice already and both times looked like a detector bug.
2. A `[[sample]]` block in `labels.toml`. `truth` is what is genuinely in the
   binary; `expect` is what each detector should currently report. If they
   differ, say why in `note` — that note is printed verbatim in the report.
3. `python -m corpus.build --only <name>` then `python -m eval.run --print`.
4. If the numbers moved, `python -m eval.run --check` will tell you
   `confidence.toml` is stale. Update it and commit both in the same change:
   data and measurement must never drift apart.
