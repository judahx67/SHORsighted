# Security policy

## Reporting a vulnerability

Report privately through [GitHub Security
Advisories](https://github.com/judahx67/SHORsighted/security/advisories/new).
Please do not open a public issue for a vulnerability.

Include the smallest input that reproduces it. If that input is a real binary,
**describe it — do not attach it.** A file path, a hash, a version, and the
offset are enough to reproduce, and this project does not accept real-world
binaries anywhere, including in a security report.

Expect an acknowledgement within a week and an assessment within two.

## Supported versions

Pre-1.0, only the latest release is supported. There are no backports.

## The threat model

**Scanned bytes are hostile.** This tool reads files nobody vetted, which is
the whole point of it. Every parse is defensive, no `assert` validates input,
and every `pefile` failure is mapped to a `PEFormatError` carrying an error
class. A malformed, truncated, or deliberately hostile PE must produce a
recorded error, never a crash, a hang, or a read outside the file.

**Filenames are attacker-controlled strings.** They come off a scanned tree and
land in the CBOM and in HTML. The report emits no JavaScript, so escaping is the
entire attack surface, and it is tested against a filename that is itself an
injection payload.

**Nothing is executed.** No sample is run, emulated, or unpacked. Analysis is
static byte inspection only, so scanning malware is not the same as running it.

**No key material is ever extracted.** The tool reports that key material exists
and where it is. It never copies the bytes. A CBOM containing a private key
would be a leak created by the tool that was supposed to inventory it.

**No network.** Scanning makes no outbound connection. Nothing is uploaded,
looked up, or reported anywhere.

### In scope

- Crash, hang, unbounded memory, or a read outside the file, from any input.
- Escape from HTML or JSON encoding via any scanned value.
- Key material, file contents, or environment data appearing in output.
- Anything that causes a sample to be executed.
- Supply-chain issues in release artifacts: a published wheel that does not
  match its attestation, or a build step that could be influenced by a PR.

### Not vulnerabilities

- **False positives and false negatives.** A missed algorithm or a spurious
  finding is a signature bug — open an issue. Measured precision and recall are
  published in [`eval/report.md`](eval/report.md), and
  [`LIMITATIONS.md`](LIMITATIONS.md) documents what this cannot see, including
  packed and .NET binaries.
- **A clean report on a binary that does use cryptography.** No findings means
  none were detected; it has never meant a binary is free of cryptography. The
  tool states this on every report it prints.

## Verifying a release

Every release is built by `release.yml` from a tag, and its artifacts carry a
signed build provenance attestation:

```
gh attestation verify shorsighted-<version>-py3-none-any.whl --repo judahx67/SHORsighted
sha256sum --check --ignore-missing SHA256SUMS
```

Publishing uses PyPI Trusted Publishing, so no long-lived API token exists in
this repository to steal.
