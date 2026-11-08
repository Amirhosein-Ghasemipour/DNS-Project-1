# patchcheck — automated security patch validation

An evidence-based validator for C/C++ security patches. It builds the pre-patch
and post-patch versions of a target, executes both under identical settings in
an isolated sandbox, and decides whether the patch actually removed the
vulnerability or introduced a functional regression. Every verdict comes from
observed program behaviour; nothing is inferred from file names, patch
identifiers, or source-text similarity.

Course project for Data and Network Security, Sharif University of Technology.
The authoritative requirements are in [`Project_1.md`](Project_1.md).

## What it does

- Builds each version twice — a normal **release** binary and an
  ASan/UBSan **sanitized** binary — and never mixes their results.
- Runs the configured test suite (valid, boundary, invalid) against both
  versions with identical limits.
- Classifies each finding as `Fixed`, `Incomplete Fix`, `New Issue`,
  `Functional Regression`, or `Inconclusive`, with a correlation record that
  says `Undetermined` unless a runtime stack actually intersects a diff hunk.
- Replays every non-trivial observation three times and flags instability.
- Minimizes each confirmed error, preserving error type and source location.
- Writes a reproducer bundle (input, commit hash, binary hash, build settings,
  environment, exact command) per error, and persists active regressions into a
  project-level suite that later runs re-execute automatically.
- Reports NX / PIE / RELRO / stack-canary status from the release ELF and warns
  when a patch weakens a protection.
- Exits with the spec's codes: `0` PASS, `10` VULN_REMAINS/NEW_ISSUE,
  `20` FUNC_REGRESSION, `30` BUILD_OR_CONFIG_ERROR, `40` INCONCLUSIVE,
  with priority `30 > 10 > 20 > 40 > 0`.

## Requirements

- Linux x86_64 (WSL2 is fine) with rootless user namespaces enabled, **or**
  a working Docker daemon.
- Python 3.10+, `gcc`, `binutils` (`readelf`), `git`, and `unshare`/`setpriv`
  for the namespace backend.

## First step in any fresh checkout

A Git checkout of this repository contains the target *source files* but not
the nested `.git` databases the pinned revisions live in, so restoring them is
a required setup step (the CI workflows do it before every job):

```bash
python scripts/restore_sources.py          # rebuild nested histories from targets/bundles
python scripts/restore_sources.py --check  # verify without changing anything
```

`targets/bundles/` holds one verified Git bundle per target repository plus
`manifest.json` recording the refs and every commit hash the configurations
pin. `scripts/package_sources.py` regenerates them (`--check` verifies they
still cover every pinned revision). The restoration step is idempotent and only
touches the nested repositories.

## Sandbox backends

There is deliberately **no host-execution mode**: targets only ever run inside
a sandbox.

`--backend namespace` (default in CI) runs the target inside an unprivileged
user namespace with `chroot`, a read-only bind of the toolchain, a private
`/proc`, no network, and `setpriv` dropping all capabilities. Wall-clock, CPU,
memory, file-size, output and process limits are enforced by a supervisor
inside the sandbox.

`--backend docker` uses a container with `--network=none`, `--read-only`,
`--cap-drop=ALL`, `--security-opt=no-new-privileges`, non-root user and cgroup
limits:

```bash
docker build --platform=linux/amd64 -t patchcheck-toolchain:1 docker/
```

## Standalone execution

Nothing below requires CI. Run everything from the repository root.

```bash
# 1. Regenerate the pinned evaluation versions, patches, and test inputs.
#    Idempotent; never resets an existing record_reader repository.
python scripts/prepare_examples.py

# 2. Validate a configuration without compiling or executing anything.
python -m patchcheck check-config configs/record-reader-correct.json

# 3. Validate one patch pair. --output must be a new directory.
python -m patchcheck run configs/record-reader-correct.json \
    --output artifacts/my-run --backend namespace
echo "exit code: $?"

# 4. Read the results.
cat artifacts/my-run/summary.txt      # developer-facing summary
cat artifacts/my-run/report.json      # structured output, all statuses
```

Generated regressions are persisted to `regressions/` (or `--suite-root`) and
re-executed automatically on the next `run`. `--no-regressions` opts out;
`--regressions DIR` adds another suite.

Regression entries record the target **and** the scenario (configuration name)
that produced them, so one durable suite root can serve several targets and
variants without replaying a reproducer against the wrong version pair. In CI
that root is `.patchcheck-suites`, restored from the Actions cache before
evaluation and saved after it, which is what makes reuse span separate
workflow executions rather than just consecutive runs in one job.

### Full evaluation matrix

Each scenario asserts an exit code derived from the spec's required outcomes
(`0`, `10`, `20`). The script exits `1` if any scenario disagrees; it also
reports how many generated regressions each scenario re-executed.

```bash
python scripts/evaluate.py --backend namespace --output artifacts/evaluation-$(date +%Y%m%d)
```

Run a subset with `--targets record-reader` or `--only record-reader-correct`.
`--fresh-suites` ignores the durable suite for a run that must start clean.

### Reproducing a reported error manually

Every bundle records the exact command, environment, commit hash and binary
hash. To re-record three additional paired executions from a bundle:

```bash
python -m patchcheck replay artifacts/my-run/reproducers/sanitized/original/manifest.json \
    --backend namespace
```

The manifest and the enclosing artifact directory must be kept together: the
manifest references the build directories and the effective configuration.

## Adding a new target

Only configuration changes are needed; no tool code mentions any target.

1. Add pinned versions (`repository` + full 40-character commit hash, plus
   optional patches/overlays) for `baseline` and `patched`.
2. Add `builds.release` and `builds.sanitized` command lists and the `binary`
   path, so both profiles are built.
3. Set `execution.interface` (`stdin`, `file`, or `argv`) and `execution.argv`.
4. Add `tests` covering `valid`, `boundary`, and `invalid` categories. Every
   test needs an `expected` block with `exit_code`, exact `stdout`, exact
   `stderr`, and a `reference` naming an independent correctness source.
5. Set `target_tests` to the inputs that reproduce the original vulnerability,
   and a short `target` identifier used to scope persisted regressions.
6. Run `python -m patchcheck check-config CONFIG` and fix anything it reports.

Correctness references for the supplied targets are in
[`targets/CONTRACTS.md`](targets/CONTRACTS.md).

## Supplied targets

| Target | Provenance | Interface | Original defect |
|---|---|---|---|
| `cjson` | DaveGamble/cJSON, pinned commit | stdin | `cJSON_SetValuestring` reads `NULL` `valuestring` |
| `jq` | jqlang/jq, pinned commit | file | missing UTF-8 bounds check reads past buffer end |
| `record-reader` | local teaching fixture | stdin | missing length check, heap overflow |

`cjson` and `jq` are real upstream projects, satisfying the "at least one real,
non-toy project" requirement; `record-reader` is a deliberately defective
fixture with a fully inspectable baseline.

Each target ships four versions — vulnerable base, correct patch, incomplete
patch, regression patch — as `configs/<target>-{correct,incomplete,regression}.json`.
Expected codes are `0`, `10`, `20` respectively.

## Layout

```
patchcheck/          validator package (no target-specific names)
  config.py          strict config validation before any build
  source.py          pinned git export, patch/overlay application, hashing
  sandbox.py         docker and namespace backends (no host mode)
  worker.py          in-sandbox supervisor: limits, capture, signals
  evidence.py        error classification, confirmation, replay comparison
  correlation.py     diff parsing, runtime/stack correlation, fix equivalence
  minimize.py        budgeted byte-level delta debugging
  hardening.py       ELF protection evidence
  runner.py          build, test, classify, bundle, persist regressions
  decision.py        exit-code priority and independent statuses
  cli.py             run / check-config / replay
configs/             one file per target and variant
targets/             pinned upstreams, harnesses, patches, inputs, CONTRACTS.md
targets/bundles/     checked-in Git bundles + manifest for clean-checkout restore
scripts/             restore/package sources, prepare_examples, evaluate, probe_sandbox
tests/               unit tests
docker/              toolchain image
```

## Interpretation limits

These are reported in every summary and are not disclaimers to skip: conclusions
are limited to the recorded inputs, builds, references and execution limits.
Absence of an observed error is not proof that all vulnerabilities are
eliminated. A new observation, or overlap between a stack trace and a diff
hunk, does not by itself prove that the patch caused it — the report records
`caused_by_patch: "Undetermined"` and the association evidence separately.
PIE does not prove runtime ASLR; canary evidence does not prove every function
is protected.
