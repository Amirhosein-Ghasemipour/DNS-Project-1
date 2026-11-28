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
- Resolves its sandbox by probing the host: the strongest available isolation
  runs, and whatever actually ran is recorded in every report and manifest.

## Requirements

- Linux x86_64 (WSL2 is fine). Python 3.10+, `gcc`, `binutils` (`readelf`),
  `git`.
- For the strongest isolation, one of: rootless user namespaces with `unshare`
  (the namespace backend), **or** a working Docker daemon with the toolchain
  image (the docker backend). When neither is available, the tool falls back
  to the restricted mode described below instead of failing the analysis.

## First step in any fresh checkout

A Git checkout of this repository — and the distributed archive — contains the
target *source files* but not the nested `.git` databases the pinned revisions
live in. The tooling restores them for you:

- `scripts/evaluate.py` runs the idempotent restoration and preparation steps
  itself before evaluating anything (`--skip-setup` opts out for CI jobs whose
  workflows restore sources beforehand), and checks the host prerequisites
  (`git`, `cc`, `readelf`) with actionable messages.
- `python -m patchcheck run` rebuilds a missing nested repository on demand
  from `targets/bundles`, so single-scenario runs work on a pristine checkout.
- The manual entry points remain available:

```bash
python scripts/restore_sources.py          # rebuild nested histories from targets/bundles
python scripts/restore_sources.py --check  # verify without changing anything
python scripts/prepare_examples.py         # regenerate pinned patches, inputs, configs
```

`targets/bundles/` holds one verified Git bundle per target repository plus
`manifest.json` recording the refs and every commit hash the configurations
pin. `scripts/package_sources.py` regenerates them (`--check` verifies they
still cover every pinned revision). The restoration step is idempotent and only
touches the nested repositories.

## Troubleshooting

`BUILD_OR_CONFIG_ERROR` (exit 30) always records its cause — read
`summary.txt`, `report.json["errors"]` and `tool-error.txt` inside the output
directory. The most common causes:

- `pinned revision ... unavailable` or `fatal: not a git repository`: the
  nested target history was not restored. Run
  `python scripts/restore_sources.py`; `scripts/evaluate.py` does this
  automatically.
- `'cc' is not on PATH` and similar: install the prerequisites listed above
  (Debian/Ubuntu: `sudo apt install build-essential git binutils`).
- `Sandbox: restricted fallback ...`: the host denies rootless user namespaces
  and Docker is not set up. Targets still ran under the supervisor's limits
  (wall-clock, memory, rlimits, capability drop); every report records the
  weaker isolation explicitly instead of claiming more than it provided.
- `evaluation setup failed: output directory already exists`: each evaluation
  writes a fresh evidence directory; pick a new `--output` name or remove the
  old one.
- `evaluation.html` in the evidence directory shows every scenario, its exit
  codes, the recorded error lines and each scenario's full console log in a
  browser; no need to open the JSON by hand.

## Sandbox backends

There is deliberately **no unsupervised host-execution mode**: targets only
ever run behind the in-process supervisor (`worker.py`), which enforces
wall-clock, CPU, memory, file-size, output and process limits, kills whole
process groups, and hands the target a clean environment and a private
temporary directory.

`--backend auto` (default) resolves the strongest *isolation envelope* the
host actually permits, by running the real pipeline once with a harmless
command:

1. **namespace** — `unshare --user --map-root-user --mount --net --pid`
   with `chroot`, a read-only bind of the toolchain, a private `/proc`, no
   network, and `setpriv` dropping all capabilities.
2. **docker** — used when the namespace probe fails and the toolchain image
   exists: `--network=none`, `--read-only`, `--cap-drop=ALL`,
   `--security-opt=no-new-privileges`, non-root user and cgroup limits
   (`docker build --platform=linux/amd64 -t patchcheck-toolchain:1 docker/`).
3. **restricted** — used when neither user namespaces nor Docker are
   available (container seccomp profiles that reject the `/proc/self/uid_map`
   write, `kernel.unprivileged_userns_clone=0`, Ubuntu 24.04 AppArmor rules,
   no Docker daemon). The supervisor's limits still apply and `setpriv`
   empties the capability bounding set where the host allows it, but there is
   **no chroot, no network namespace and no private /proc**. This degradation
   is never silent: `report.json` records the resolved mode, the exact
   underlying reason, what was and was not provided; `summary.txt` prints a
   sandbox note; every reproducer manifest carries the same identity.

`--backend namespace`, `--backend docker` and `--backend restricted` force a
backend; `namespace` still falls back (docker, then restricted) when its probe
shows the host denies it, and records why.

### Running the tests in containers

The execution-environment requirement — all tests in an isolated environment
such as a container with resource limits — is satisfied directly by the docker
backend: every build and every test execution runs in its own container from
the toolchain image with `--network=none`, `--read-only`, `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, a non-root user and cgroup memory/CPU/PID
limits. One command prepares everything and runs the full matrix this way:

```bash
scripts/run-in-docker.sh                     # full 9-scenario matrix
scripts/run-in-docker.sh --only cjson-correct
scripts/run-in-docker.sh --targets record-reader
scripts/run-in-docker.sh --inside            # the entire pipeline inside one container
```

The default mode runs patchcheck on the host and forces `--backend docker`;
the tool itself creates and destroys one hardened container per build and per
execution, and each `report.json` records the image id and the options that
actually ran. The `--inside` mode instead runs restore, prepare and the
evaluation inside a single resource-limited container; within it, patchcheck's
own probe usually still resolves to `restricted` (Docker's default seccomp
profile denies user namespaces), which is the honest result — the outer
container is the isolation layer and the report says exactly that.
`PATCHCHECK_IMAGE=name:tag` overrides the image tag.

Root vs. non-root invocations are both supported, with the container always
non-root: run normally when your account is in the `docker` group, or with
`sudo` when it is not. As your own user, each container maps to your uid/gid,
which already owns the freshly created build directories. Under `sudo` the
build directories would be root-owned while the container stays uid 1000, so
the backend hands each build tree to that user with an explicit `chown` before
its build — recorded as `sandbox_preparation` next to the sandbox identity in
`report.json` — without ever widening the container's privileges (this was the
root cause of `ld: cannot open output file target: Permission denied` in
earlier builds). The script also detects root-owned `targets/`/`artifacts/`
leftovers from earlier `sudo` runs when invoked without root and prints the
one-line `chown` fix instead of failing deep inside preparation, and prints
the same fix after a `sudo` run finishes. If a build is ever killed by the
container's memory limit, the report records `resource_limit:
container_memory` rather than a tool crash. On hosts whose primary user is not
uid 1000, container-written build files are owned by uid 1000;
`sudo chown -R "$(id -u):$(id -g)" artifacts` reclaims them.

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
    --output artifacts/my-run
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
python scripts/evaluate.py --output artifacts/evaluation-$(date +%Y%m%d-%H%M%S)
```

Run a subset with `--targets record-reader` or `--only record-reader-correct`.
`--fresh-suites` ignores the durable suite for a run that must start clean.

Every evaluation writes `evaluation.html` next to `evaluation.json`: a
self-contained report (no JavaScript, opens offline) listing every scenario
that ran — expected vs. actual exit code, OK/FAILED verdict, generated
re-executions, persisted regressions, recorded error lines, the full
`summary.txt` verdict and the complete console log of each scenario. To
rebuild it from an evidence directory that predates this feature, without
running anything again:

```bash
python scripts/make_html_report.py --output artifacts/evaluation-20251111-143005
```

### Continuous integration

`.github/workflows/evaluate.yml` runs the full matrix on every push and pull
request, with no target-specific steps — onboarding a new target (below)
never requires touching the pipeline. The job:

1. restores the durable per-scenario regression suites from the Actions cache,
   so minimized reproducers from one run are re-executed by the next
   (the spec's generation-then-re-verification round-trip across CI jobs);
2. builds the toolchain image for the docker sandbox fallback and probes
   which isolation envelope the runner actually permits
   (`scripts/probe_sandbox.py`);
3. runs `scripts/evaluate.py`, which restores the nested git histories itself
   and gates the job on the scenario contract — the job fails (exit 1) when
   any actual exit code disagrees with the expected one;
4. publishes all evidence, including `evaluation.html`, as workflow artifacts,
   and writes a markdown results table into the job summary.

`workflow_dispatch` accepts a `backend` override and a `targets` filter for
debugging a single target. On other CI systems the same shape applies: restore
`--suite-root` from the pipeline cache, run `scripts/evaluate.py` with a fresh
`--output` per build number, publish the evidence directory, and fail the
pipeline on a non-zero exit.

### Reproducing a reported error manually

Every bundle records the exact command, environment, commit hash and binary
hash. To re-record three additional paired executions from a bundle:

```bash
python -m patchcheck replay artifacts/my-run/reproducers/sanitized/original/manifest.json
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
scripts/           restore/package sources, prepare_examples, evaluate, HTML report, probe_sandbox
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
