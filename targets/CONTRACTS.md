# Target behaviour contracts (independent correctness reference)

This document is the **independent reference** for every `expected` block in
`configs/*.json`, as required by §2 of `Project_1.md` ("Definition of Correct
Program Behavior"). It is written from each target's own documentation, public
API contract, or an external standard — never from the patched program's
observed output.

Every test's `expected.reference` field cites a section here. Changing an
expectation without changing this document means the reference is no longer
independent, and the run no longer proves correctness.

The tool never treats a target's own output, or any language model, as the
authority for correct behaviour. `scripts/prepare_examples.py` encodes the
oracles below; `patchcheck` only compares observations against them.

---

## Shared conventions

All three targets read their input from the interface named in
`execution.interface`, emit exactly one line on stdout, and use exit code `0`
for accepted input and `2` for rejected input. `3` indicates an internal
environment failure (I/O error, allocation failure, unusable argument) and is
never an expected value.

stdout comparisons are exact byte-for-byte matches after UTF-8 decoding,
including the trailing newline. stderr must be empty on any path the tool
accepts as correct: an accepted run that writes diagnostics is a mismatch.

---

## 1. `record_reader` — local teaching fixture

**Provenance.** Deliberately defective fixture authored for this project
(`targets/record_reader/base.c`). It is *not* a real-world library; it exists to
give a small, fully-inspectable baseline with an unambiguous memory error. The
two real projects below carry the "real, non-toy" requirement of §4.

**Contract.** The program reads one record from stdin and echoes it.

| Input length | Accepted | stdout | exit |
|---|---|---|---|
| `0 ≤ n ≤ 16` | yes | the input bytes, verbatim, no added newline | `0` |
| `n > 16` | no | `too long\n` | `2` |

The 16-byte limit is the allocation size the record is copied into. The
contract is stated in terms of the record length only: it must not depend on
the *contents* of the record. Any implementation that rejects a `length ≤ 16`
record, or accepts a `length > 16` record, violates this contract regardless of
what bytes are involved.

Corollary used by the boundary tests: the empty record (`n = 0`) is a valid,
accepted record and must produce an empty stdout line with exit `0`. A patch
that special-cases empty or short input is a functional regression, not a
tightening of the limit.

Corollary used by the `minimized_expected` overrides: every input that
overflowed the 16-byte allocation necessarily has `n > 16`, so *any* reduced
input that still triggers the same error must also be rejected with
`too long\n` / `2`. The expected result is therefore input-independent for
this family, which is what makes reduction sound.

**Baseline defect.** The baseline omits the length check and copies `n` bytes
into a 16-byte heap allocation (`memcpy`). Observable consequences:

- Sanitized build: an ASan out-of-bounds write inside `main` at the `memcpy`
  call site. GCC's FORTIFY interposition reports this as
  `ERROR: AddressSanitizer: unknown-crash` with `WRITE of size <n>` and a
  `is located 0 bytes to the right of 16-byte region` trailer; the access
  direction and region kind are present, so the tool classifies it as a
  heap-buffer-overflow rather than treating it as unclassified.
- Release build: `_FORTIFY_SOURCE` (enabled by `-O2`) aborts via `__chk_fail`
  with `*** buffer overflow detected ***`, i.e. `SIGABRT`. This is a real
  observation of the same defect and is reported separately from the sanitized
  build, per §3.2.

**Known-good variants** (the three patches under test, from
`targets/record_reader/versions/`):

- `correct`: rejects `n > 16` with `too long\n` / `2`, accepts everything else.
- `incomplete`: rejects only `n == 64`, so `n == 48` still overflows.
- `regression`: correctly rejects `n > 16` but additionally rejects `8 < n ≤ 16`,
  breaking valid records that the contract accepts.

---

## 2. `cjson` — DaveGamble/cJSON

**Provenance.** Upstream project, pinned to commit
`87d8f0961a01bf09bef98ff89bae9fdec42181ee`. Only `cJSON.c` is compiled, via the
local driver `targets/cjson/harness.c`; no upstream file is modified except by
the explicit patches in `targets/cjson/patches/`.

**Contract** — `cJSON_SetValuestring(object, valuestring)`, from the public
header documentation:

- On success it replaces `object->valuestring` and returns the new pointer.
- It returns `NULL` when the object is not a string, when the object is a
  corrupted string whose `valuestring` is `NULL`, or when allocation fails.

The driver maps this to the interface below. A leading `!` builds the corrupted
string object described by the upstream regression test (`type = cJSON_String`,
`valuestring = NULL`); a leading `=` builds a healthy string object seeded with
`"seed"`. Any other first byte, an empty input, a NUL byte in the input, or an
input that fills the 4096-byte buffer is rejected by the driver itself.

| Input | Meaning | stdout | exit |
|---|---|---|---|
| `=hello` | update healthy object | `hello\n` | `0` |
| `=university` | update healthy object | `university\n` | `0` |
| `=` (empty replacement) | update to empty string | `\n` | `0` |
| `?` | unrecognised selector | `invalid\n` | `2` |
| `!original` | corrupted object, `NULL` field | `invalid\n` | `2` |
| `!alternate` | corrupted object, `NULL` field | `invalid\n` | `2` |

The empty replacement (`=`) is the boundary case: replacing a string with the
empty string is valid and must yield an empty line, not a rejection. `strlen`
of an empty string is `0`, which the function must accept.

Corollary used by the `minimized_expected` overrides: the contract for a
corrupted object depends only on `valuestring == NULL`, never on the
replacement bytes. Any reduced input that still starts with `!` must therefore
be rejected with `invalid\n` / `2`.

**Baseline defect.** The baseline omits the `valuestring == NULL` guard, so
`cJSON_SetValuestring` calls `strlen(NULL)`. UBSan reports
`null pointer passed as argument 1, which is declared to never be null` with a
frame in `cJSON_SetValuestring`; the release build segfaults.

**Known-good variants:**

- `correct`: reinstates the upstream guard.
- `incomplete`: guards only when the replacement is exactly `original`, so
  `!alternate` still reaches `strlen(NULL)`.
- `regression`: keeps the guard but rejects non-empty replacements on the
  healthy path, breaking `=hello` and `=university`.

---

## 3. `jq` — jqlang/jq UTF-8 validator

**Provenance.** Upstream project, pinned to commit
`11c528d04d76c9b9553781aa76b073e4f40da008`, file `src/jv_unicode.c`. The driver
`targets/jq/harness.c` calls the real `jvp_utf8_is_valid` from the library; no
upstream file is modified except by the explicit patches under
`targets/jq/patches/`.

**Contract** — RFC 3629 §4 UTF-8 grammar, which is what `jvp_utf8_is_valid`
implements:

| Input (hex) | Meaning | stdout | exit |
|---|---|---|---|
| `68656c6c6f` | `hello`, ASCII | `valid\n` | `0` |
| `e282ac` | `€`, U+20AC | `valid\n` | `0` |
| `` (empty file) | empty string | `valid\n` | `0` |
| `f48fbfbf` | U+10FFFF, the maximum scalar value | `valid\n` | `0` |
| `eda080` | U+D800, an encoded surrogate | `invalid\n` | `2` |
| `e2` | truncated 3-byte sequence | `invalid\n` | `2` |
| `f0` | truncated 4-byte sequence | `invalid\n` | `2` |

The empty file and U+10FFFF are the boundary cases. The empty string is valid
UTF-8: the validator must accept it without reading past the buffer. U+10FFFF
is the highest legal code point and must be accepted; `U+110000` and the
surrogate range `U+D800`–`U+DFFF` must not.

Corollary used by the `minimized_expected` overrides: a truncated multi-byte
sequence can only be reduced to another truncated sequence, so any input that
still triggers the same read-past-`end` error must be `invalid\n` / `2`.

**Baseline defect.** The baseline removes the `in + length > end` bounds
check, so a truncated sequence reads past the end of the exact-sized heap
buffer allocated by the driver. ASan reports a heap-buffer-overflow whose
top frame is in `jvp_utf8_is_valid`.

**Known-good variants:**

- `correct`: reinstates the upstream bounds check.
- `incomplete`: applies the check only when the leading byte is `0xe2`, so
  `f0` (leading byte `0xf0`) still reads out of bounds.
- `regression`: forces `codepoint = -1`, rejecting all valid input including
  `hello`.

---

## Why these references are independent

Each oracle above is derived from a source external to this tool and to the
patched binary: an explicit written contract, a published API guarantee, or
RFC 3629. None was obtained by running the patched build and recording what it
printed. `scripts/prepare_examples.py` transcribes these tables; if a table
entry and a config `expected` block ever disagree, the config is wrong.

Approval status: approved. The source provenance, patches, reference tests, and
expected results above were approved during the design phase, as required by §2
and §4 of `Project_1.md`.
