# Project 1 — Automated Security Patch Validation and Regression Testing in CI/CD

**Sharif University of Technology**  

Department of Computer Engineering  

Course: Data and Network Security  

Instructor: Solmaz Salimi  

**Publication Date:** 28 Mehr 1405  

**Submission Deadline:** 18 Aban 1405  

**Project Weight:** 2.5 out of 20  

**Group Size:** 4 students

*English translation of Sections 1–4 of the original Persian project specification. Technical requirements, terminology, classifications, and numerical specifications are preserved.*

---

## 1. Project Objective and Problem Statement

Applying a security patch does not necessarily mean that a vulnerability has been completely eliminated. Sometimes, a patch is incomplete and can be bypassed using a different input. In other cases, a patch introduces a functional regression, disrupting the program's normal behavior.

The primary objective of this project is to develop an automated tool integrated into a **CI/CD pipeline**. This tool must not merely function as a static scanner or a report aggregator. Instead, through actual program execution, it must answer two fundamental questions:

1. After reproducing the original security vulnerability in the baseline version, does the same vulnerability still occur in the patched version within the defined scope of testing?

2. Has the patch preserved the program's correct and expected functionality when processing valid inputs?

The tool must be capable of correlating observed vulnerabilities and errors with the code modifications introduced by the patch (Diff) and producing reproducible evidence.

**The absence of an observed error during testing does not constitute proof that all vulnerabilities have been eliminated.**

## 2. Supported Scope and Fundamental Requirements

To ensure consistent evaluation and prevent groups from selecting exclusively script-based targets or performing superficial analyses, compliance with the following requirements is mandatory for all groups.

### Target Program

The target programs must meet the following specifications:

- They must be compilable programs written in **C or C++**.

- They must be executable in the **ELF (Executable and Linkable Format)** format.

- They must run on **Linux (x86_64)**.

- They must accept input through at least one of the following interfaces:

  - Files

  - Command-line arguments

  - Standard input (`stdin`)

The source code for both program versions must be available, and both versions must be buildable.

Python scripts, web applications, and interpreted code are **not permitted as target programs**.

However, this restriction does not apply to the programming language used to implement the validation tool itself.

### Mandatory Dynamic Execution

Actual execution of the target program and dynamic testing are mandatory for every group.

Relying exclusively on Static Application Security Testing (SAST) tools or textual inspection of source code is not acceptable.

### Generalizability

The tool must not depend on the names of functions or the internal structure of a particular target program.

Adding a new target program must be possible solely by modifying a configuration file that specifies:

- The build command

- The path to the executable binary

- The method used to provide input

- The collection of test cases

### Definition of Correct Program Behavior

Before evaluation begins, the criteria for determining correct program behavior must be defined using the program's documentation or independent reference tests and approved by the instructor.

These criteria must cover:

- Expected behavior for valid inputs

- Expected behavior for invalid inputs

- Expected program output

- Expected exit code

The patched program's output or the judgment of a language model, by itself, must not be considered an authoritative correctness reference.

---

## 3. Expected Tool Capabilities

### 3.1. Patch Validation and Correlation of Findings with Code Changes (Core Component)

The tool must receive and compare:

- The pre-patch version of the program

- The post-patch version of the program

- The code differences between the two versions (`Git Diff`)

#### Patch-to-Finding Correlation

This component is a core requirement of the project.

The tool must demonstrate how an error that has been fixed, remains present, or is newly observed during testing is related to the modifications introduced by the patch.

Evidence supporting this correlation may include:

- Matching the stack trace or execution path to the modified file, function, or section of code.

- Comparing the runtime execution of the two program versions.

The location where an error occurs is not necessarily on a modified line of code.

For example, modifying a length check in a calling function may affect an error that occurs in another function.

The apparent proximity of a static-analysis warning to a modified code location is not sufficient evidence of correlation.

If the available evidence is insufficient, the correlation must be reported as **Unknown or Undetermined**.

#### Classification of Finding Status

The report must distinguish findings using the following four categories:

1. **Fixed:** The vulnerability or error has been eliminated within the scope of the performed tests.

2. **Incomplete Fix:** The patch is incomplete, or the original vulnerability remains present.

3. **New Issue:** A new error has been observed.

4. **Functional Regression:** The patch has disrupted previously correct program functionality.

An additional **Inconclusive** status is also required when there is insufficient evidence to reach a conclusion.

The observation of a new error does not, by itself, establish that the patch caused that error.

Every error-triggering input must be executed against both versions using corresponding execution settings.

Furthermore, to classify a finding as a functional regression, the tool must demonstrate that:

- The baseline version exhibited the expected behavior defined by an independent reference.

- The patched version violated that expected behavior.

### 3.2. Dynamic Testing and Detailed Error Reporting

The tool must test the patched version against both:

- Functional tests, including valid inputs

- Boundary-condition tests and invalid inputs

If an error or unexpected crash occurs, the report must record the following information separately.

#### Error Type

Examples of error types include:

- Stack buffer overflow

- Heap buffer overflow

- Use-After-Free (`UAF`)

- Null-pointer dereference

- Division by zero

This classification must not be confused with root-cause analysis. Identifying the type of error is not equivalent to identifying its underlying cause.

#### Detection Mechanism

The report must specify how the error was detected.

Possible detection mechanisms include:

- Operating-system signals

- Binary-level protections, such as stack-canary checks and calls to `__stack_chk_fail`

- Runtime error-detection tools (Sanitizers), including:

  - AddressSanitizer (`ASan`)

  - UndefinedBehaviorSanitizer (`UBSan`)

#### Program Termination

The following information must be recorded:

- Exit code

- Received signal, such as `SIGSEGV` or `SIGABRT`

- Standard output (`stdout`)

- Standard error (`stderr`)

Exceeding time limits or resource limits must be reported separately.

Not every program crash necessarily represents an exploitable security vulnerability.

#### Distinguishing Release Builds from Instrumented Builds

The execution results of a normal binary (**Release Build**) must not be mixed with those of an instrumented or sanitized binary (**Instrumented/Sanitized Build**).

The tool must execute and report these two build types separately.

This separation is required to determine:

- How an error manifests in the final, regular binary

- What additional details are available from the instrumented build

Pre-patch and post-patch comparisons must be performed using corresponding build types.

#### Test-Suite Requirements

Each group must design and document a collection of:

- Valid test inputs

- Boundary-condition test inputs

- Invalid test inputs

This collection must be executed against both program versions and their corresponding build configurations using identical settings and resource limits.

### 3.3. Reproducibility, Automated Input Minimization, and Regression Testing

Every confirmed error must be reproducible.

#### Reproducer Bundle

For each error, the tool must save a reproduction package containing:

- The input file that triggers the error

- The exact program version identifier (`Commit Hash`)

- The binary hash

- Build settings

- Relevant environment variables

- The complete execution command

This information must be sufficient to reproduce the same error when the program is executed again.

The results of **at least three replay executions** must be recorded.

Unstable or non-deterministic cases must be explicitly identified.

#### Automated Testcase Minimization

The tool must automatically reduce the size of the error-triggering input.

This may be accomplished using techniques such as:

- Gradual removal of bytes

- Delta Debugging or similar techniques

The minimized input must continue to trigger **the same type of error at the relevant location**.

Both the original input and the minimized input must be preserved.

A nonzero exit code alone is not sufficient evidence that the minimized input reproduces the same error.

#### Automatic Regression Test Generation

The minimized input must automatically be added to the project's regression test suite.

This ensures that it will be checked during subsequent executions of the CI/CD pipeline.

The generated regression test must:

1. Expose the expected error in the baseline version.

2. Verify that the same error does not occur in the patched version.

3. Verify that the patched version exhibits the expected behavior.

### 3.4. Basic Binary Hardening Assessment

The tool must examine the security protections present in the normal (release) ELF binary.

These protections include:

- `NX` — Non-Executable Memory

- `PIE` — Position-Independent Executable

- `RELRO` — Relocation Read-Only

- `Stack Canary` — Stack-Smashing Protection

The tool must report the status of these protections together with supporting evidence.

If an unintended change occurs in the new version, the tool must generate a warning.

For example, modifying a build script might accidentally disable a security protection.

For `RELRO`, the protection level must be reported as one of the following:

- No RELRO

- Partial RELRO

- Full RELRO

The presence of `PIE` does not prove that Address Space Layout Randomization (`ASLR`) is enabled in the runtime environment.

Similarly, the presence of stack-canary-related evidence in a binary does not imply that all functions are protected.

### 3.5. Automated Execution in CI/CD and Standardized Exit Codes

The tool must be executable from the command line.

It must generate two types of output:

1. A readable summary report intended for developers.

2. Structured output in `JSON` format.

The tool's exit code must precisely and unambiguously indicate the execution status so that the CI/CD pipeline can make decisions based on it.

The required exit codes and their meanings are as follows.

#### Exit Code 0 — `PASS`

The targeted error has been reproduced in the baseline version but is not observed in the patched version within the scope of testing.

Additionally, no other confirmed security error has been recorded in the patched version, and all functional tests and mandatory checks have been completed successfully.

#### Exit Code 10 — `VULN_REMAINS` / `NEW_ISSUE`

The original vulnerability still occurs (`VULN_REMAINS`), or another memory-related or security error has been confirmed using valid evidence (`NEW_ISSUE`).

An unclassified crash alone is not sufficient to confirm a vulnerability.

#### Exit Code 20 — `FUNC_REGRESSION`

At least one valid functional test that passed in the baseline version fails in the patched version.

This condition must be recorded independently of whether the security vulnerability has been fixed.

#### Exit Code 30 — `BUILD_OR_CONFIG_ERROR`

The target program cannot be compiled, the configuration file is incomplete, or an error exists in the execution environment or validation tool itself.

These conditions must not be treated as equivalent to discovering a security vulnerability or successfully validating a patch.

#### Exit Code 40 — `INCONCLUSIVE`

A mandatory check has not been completed, or the available evidence is insufficient to reach a conclusion.

Examples include:

- Failure to reproduce the baseline vulnerability

- An unstable or non-deterministic finding

- An unclassified crash

#### Exit-Code Priority

If multiple conditions occur simultaneously, the exit-code priority must be:

**30 > 10 > 20 > 40 > 0** (highest priority to lowest priority).

All findings and the independent statuses of security, functionality, and analysis completeness must remain available in the `JSON` output, together with supporting evidence, program versions, and execution configurations.

---

## 4. Final Testing and Evaluation Scenarios

Your tool must be tested and submitted using **two independent C/C++ programs**.

At least one of these programs must be a real, non-toy project or library.

The group is responsible for:

- Selecting the target programs

- Preparing the required program versions

The following information must be approved by the instructor during the design phase:

- The provenance or origin of the source code

- The patches

- The reference tests

- The expected results

Using a publicly known vulnerability and its corresponding public patch is permitted.

**Discovering a new vulnerability is not a requirement.**

For each of the two programs, the following four versions must be prepared and made available in the project repository.

### Version 1 — Vulnerable Base

The baseline vulnerable version must contain **at least one reproducible memory error**.

### Version 2 — Correct Patch

The correct patch must satisfy both conditions:

- The original error is not observed within the defined evaluation scope.

- All functional tests pass successfully.

**Expected output after complete execution: Exit Code `0`.**

### Version 3 — Incomplete Patch

The incomplete patch must block only the original input that triggered the vulnerability.

However, the vulnerability must still occur when a different input is supplied.

This alternative input must be:

- Designed by the group

- Included in the test suite

**Expected output: Exit Code `10`.**

### Version 4 — Regression Patch

The regression-inducing patch must prevent the targeted error from occurring during testing.

However, it must also disrupt the program's normal behavior for a subset of valid inputs.

Provided that no other confirmed security vulnerability is present:

**Expected output: Exit Code `20`.**

### Testing on the Defense Day

In addition to the scenarios described above, several **unseen patches** will be provided during the project defense session.

These patches will be applied to the target programs or to another program belonging to the same family.

The unseen patches will remain within the defined project scope and use the previously agreed input interface.

Your tool must evaluate these patches **live during the defense session**.

The tool's response must not be determined using:

- File names

- Previously known patch identifiers

In other words, the tool must perform actual validation rather than rely on predefined answers associated with particular files or patches.

Additional implementation requirements from Sections 5–6:

1. Execute all target-program tests inside an isolated, resource-limited environment, such as a container. Test only permitted targets.

2. Make patch-validation decisions exclusively from actual execution results and objective, reproducible evidence. An LLM may assist development or preliminary analysis, but must not replace deterministic validation logic. Identical evidence must yield identical conclusions.

3. Implement a modular architecture with independently understandable and testable components.

4. Supply the complete runnable project: tool source code, configuration files, exact target versions, test suite, reproducer bundles, generated reports, CI/CD pipeline file, and instructions for standalone execution.

5. Ensure that each capability works under independent evaluation rather than only on hard-coded or selected test cases. Support evaluation of previously unseen patches within the specified scope.

6. Keep the architecture and configuration sufficiently clear to support limited modifications during technical defense.
