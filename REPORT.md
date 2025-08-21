<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 1Password Secrets Action — Security and Production Readiness Audit

Last updated: 2025-08-18

This report evaluates the security posture, production readiness, and logging safety of the 1Password Secrets Action
in this repository. The analysis focuses on avoidance of credential leakage, supply-chain controls, validation
boundaries, operational safety in GitHub Actions, and observability that does not compromise secret data.

Scope includes:

- Composite action wrapper: `action.yaml`
- Command-line entry point and app orchestration
- Internal packages for configuration, logger, audit/monitoring, CLI lifecycle and execution, authentication, output handling, secret retrieval, and validation
- Memory hygiene utilities

Note: This audit reflects the current codebase as observed in this repository (not external forks or
historical variants).

---

## Executive Summary

Overall, the action demonstrates a solid security design with defense-in-depth:

- Secrets never travel on the command line; token must be provided via environment only.
- The default execution builds the tool from source locally; when downloading, the composite action enforces
  checksum verification.
- The 1Password CLI ("op") is pinned to known versions and verified via vendor-supplied checksums before execution.
- Secret values flow through purpose-built secure containers (locked memory and multi-pass zeroing), are scrubbed
  in logs, and are masked before being written to `GITHUB_OUTPUT`/`GITHUB_ENV`.
- The action validates the GitHub Actions environment and refuses to write outputs/env when the appropriate files
  are unavailable.
- CLI subprocesses run with a minimal, curated environment; authentication is performed via environment variables,
  not flags.

The repository is suitable for production use after addressing a handful of low-to-medium risk findings and
quality-of-life changes that improve resilience and observability without weakening secrecy. No critical
credential-leak paths were found under normal operation.

---

## Strengths

Security-by-default choices are consistent and well-implemented:

- Token handling and inputs
  - Token must be present in environment (`INPUT_TOKEN`/`OP_TOKEN`); the CLI token flag is removed.
  - Token format is strictly validated (service account tokens), with consolidated validation and sanitization available for logging contexts.

- Supply-chain controls
  - Composite action builds the binary locally by default.
  - If a custom download URL for the action binary is used, a checksum is required and verified.
  - The 1Password CLI manager pins version(s) and verifies SHA256 checksums for the extracted binary from the official distribution URLs. Binaries are placed with restrictive permissions.

- Child-process and environment hygiene
  - Minimal environment is propagated to child processes (only `PATH`, `HOME`, `USER`, temp variables, plus the authentication-specific envs).
  - Authentication material is provided to the CLI via environment variables (`OP_SERVICE_ACCOUNT_TOKEN`), not flags.
  - Arguments for `op` are validated (flag allow-list, traversal checks) and never interpolated in a shell.

- Output safety in GitHub Actions
  - Uses `GITHUB_OUTPUT` and `GITHUB_ENV` files (0600) and refuses to operate if those files are not present.
  - Multi-line values are written via heredoc with a crypto-random delimiter. Values are masked via `::add-mask::` before being written as outputs/env.
  - Output and env names are validated; reserved prefixes and dangerous names (e.g., `PATH`) are denied.

- Memory hygiene
  - SecureString allocates page-aligned buffers where possible, attempts to lock memory (`mlock`/`VirtualLock`) and executes multi-pass zeroing on `Zero/Destroy`.
  - Core dumps are disabled on Unix platforms to avoid memory residue leaks.

- Observability that respects secrets
  - Logger supports context-aware scrubbing and "sensitive" variants of `Info/Warn/Error/Debug`, plus GitHub
    grouping and summaries.
  - Errors and audit/monitoring streams avoid logging secret values; when error text may be untrusted, sensitive
    context is used and additional scrubbing is applied.

---

## Detailed Findings

Severity levels: High, Medium, Low. Actionable recommendations follow each item.

### 1) Logger scrubbing coverage could be broadened (Medium)

- What: The logger’s secret detection for value scrubbing intentionally focuses on 1Password service account tokens (e.g., `ops_…` + exact length) and a set of indicator substrings. While this precision avoids false positives, it risks missing atypical or future token formats, or other credentials accidentally included in error strings (e.g., bearer tokens, API keys returned by third-party tooling).
- Risk: Low-to-medium. Many call sites already route untrusted/error strings through “sensitive” logging paths, and the validator/engine scrubs errors with regex. Still, broader patterns would improve defense-in-depth.

Recommendations:

- Expand `IsSecretValue` and scrubbing to include:
  - Generic bearer tokens (`Authorization: Bearer …`),
  - Long high-entropy strings (e.g., base64/hex-32+),
  - Common token prefixes from providers (AWS, GCP, Azure) if applicable.
- When writing GitHub summaries (`GitHubSummaryError`), run the error string through the same scrubber to remove any overlooked sensitive fragments.

Impact: Improves resilience to developer mistakes and evolving token formats with negligible runtime overhead.

---

### 2) Heredoc delimiter collision check (Low)

- What: `output` handling generates a random heredoc delimiter but does not check whether that delimiter appears inside the value before writing to `GITHUB_OUTPUT`/`GITHUB_ENV`.
- Risk: Very low. Random 8-byte hex delimiter makes collisions extremely unlikely, but a deterministic check can eliminate even theoretical cases.

Recommendations:

- After generating the delimiter, check if it occurs within the value; regenerate until it does not.

Impact: Belt-and-suspenders hardening for multiline outputs.

---

### 3) CLI download size limit may be too restrictive (Operational/Medium)

- What: The `op` download is limited by a 10 MB reader cap during download/extract. Some official CLI archives may exceed this size over time.
- Risk: Operational failure rather than security weakness: downloads might fail with partial reads or checksum mismatches. From a security standpoint, having a size cap is good; it just needs to be realistically high and ideally validated against advertised `Content-Length`.

Recommendations:

- Increase the maximum allowed size (e.g., 100–200 MB), or:
  - Read `Content-Length` and enforce a reasonable upper bound with a clear error when exceeded.
- Keep checksum verification mandatory; do not disable.

Impact: Prevents spurious verification failures while retaining protections against resource exhaustion.

---

### 4) Secret item names and field names appear in audit logs (Low)

- What: Audit records (e.g., “secret resource” includes `secretName/fieldName` and vault name). While values are never logged, some organizations treat secret item names as sensitive metadata.
- Risk: Low. This is often acceptable; however, some operating models consider item names sensitive.

Recommendations:

- Provide a configuration knob to hash or redact secret item names in audit/monitor logs while still correlating internally (e.g., `sha256(itemName)`).
- Document current behavior clearly in SECURITY.md for operators with stricter requirements.

Impact: Optional privacy enhancement for regulated environments without breaking observability.

---

### 5) Token lifetime in Go heap when bridging to string (Low)

- What: To interact with the CLI and with GitHub outputs/env, secrets are temporarily materialized as Go strings. This is largely unavoidable given upstream APIs and GitHub file formats.
- Risk: Low. The code already uses SecureString for at-rest handling and secure destruction semantics; string lifetimes during I/O are short.

Recommendations:

- Document this trade-off explicitly in SECURITY.md, clarifying the design boundaries and mitigation (short-lived scope, process isolation on ephemeral runners).

Impact: Improves transparency; no code changes required.

---

### 6) Broaden environment variable deny-list if your use cases warrant (Low)

- What: The `output` env name validator already denies `PATH`, preload/library hooks, language options, SSH/GIT injection vectors, etc. This is strong and practical.
- Risk: Low. Some installations may want to deny additional environment families (e.g., cloud provider credential variables, docker/rootless envs).
- Recommendation:
  - Make the deny-list extensible via configuration, allowing administrators to add entries without recompiling.

Impact: Aligns with varying organizational policies without compromising defaults.

---

### 7) Error propagation into GitHub summary (Low)

- What: The “error summary” helpers show the error text in the step summary. While inputs flowing there are typically scrubbed or sanitized upstream, enforcing scrub at this final presentation layer is prudent.
- Risk: Low, but it’s a high-visibility surface.
- Recommendation:
  - Apply the logger’s sanitize/scrub routine to any free-form error text before including it in summaries.

Impact: Eliminates a class of unlikely but impactful display leaks.

---

## Credential Leakage Review

- Composite action:
  - Credentials are never passed as CLI flags.
  - Secrets are only provided via environment variables to the action and to the 1Password CLI (`OP_SERVICE_ACCOUNT_TOKEN`).
  - The wrapper prints build metadata, checksum verification status, and (when using custom downloads) the URL — none of which are sensitive.

- Process execution:
  - The child process env is minimal; only authentication env is added intentionally.
  - No secret values are written to stdout/stderr by the action; they are emitted to `GITHUB_OUTPUT`/`GITHUB_ENV` and masked beforehand.

- Logging and summaries:
  - “Sensitive” logging paths scrub strings.
  - Configuration logging uses `SanitizeForLogging()` and does not include vault/item values; it logs counts and booleans (e.g., whether token present) rather than raw values.
  - Suggestion: sanitize error text prior to GitHub summary output.

- Validation and parsing:
  - Inputs undergo strict validation including detection of injection and undesirable patterns.
  - Record parsing enforces strict formats (single or structured) with bounded depth and character sets.

Conclusion: The current implementation exhibits strong default secrecy with sound boundaries. With the small scrubbing and summary-hardening improvements suggested, credential leakage risk is very low.

---

## Supply Chain and Binary Integrity

- Action binary:
  - Built locally by default; if `download_url` is used, the composite step requires `checksum` and verifies it before execution.

- 1Password CLI:
  - Version pinned (or resolved to default “latest known good” internally) and hashed via SHA256 verification after extraction.
  - Downloads from the official base URL. In case of custom URLs, checksum verification remains enforced via the expected SHA for the selected version.

- Permissions:
  - Files and temp outputs are opened with secure modes (`0600` for files; executables with minimal required permissions).
  - Cache directories are created with restrictive permissions.

Recommendations:

- Ensure a documented process and cadence for updating the versions database and checksums (e.g., via release automation).
- Consider supporting attestations (SLSA provenance) if 1Password publishes such metadata in the future.

---

## Observability and Auditing

- The monitoring layer integrates with the logger and audit trail to track:
  - Operations, outcomes, durations, and component metrics.
  - Authentication, vault resolution, and secret retrieval events (without secret values).
- Audit buffering and periodic flushing avoid noisy synchronous I/O, while log levels remain appropriate (info/warn/error).
- GitHub step summaries show safe aggregated information.

Recommendations:

- Add a configuration switch to redact/hide item names if policy demands.
- Ensure large, multi-run pipelines can persist audit artifacts as workflow artifacts if operators want retention.

---

## Maturity and Production Readiness

- Input validation is comprehensive and centralized.
- Error handling is structured with error codes and user-facing suggestions.
- Memory hygiene is robust, including mlock/VirtualLock and multi-pass zeroing.
- Output handling strictly adheres to GitHub best practices (files not deprecated commands).
- Tests cover validation, environment checks, and core flows.

Gaps and to-dos:

- Increase download size ceiling for the `op` archive or enforce a content-length-based bound.
- Slightly broaden secret scrubbing patterns and apply them in summary rendering.
- Optional: introduce configuration for redacting item names in audit/monitoring.

Verdict: Ready for production with the minor refinements above.

---

## Prioritized Action Plan

1) Reliability hardening (Medium)

- Increase the `op` download max size or enforce via Content-Length with a generous cap.
- Keep checksum verification and limiters in place.

1) Secrecy hardening (Medium/Low)

- Expand secret scrubbing patterns in the logger (bearer tokens, generic high-entropy strings).
- Scrub error strings before writing GitHub summaries.

1) Output handling QoL (Low)

- Add delimiter-in-value check for heredoc and regenerate if needed.

1) Policy flexibility (Low)

- Make env var deny-list extensible via configuration.
- Add a config option to hash/redact item names in audit/monitor logs.

1) Documentation (Low)

- Document the brief moments where strings must be created for outputs/env, and why this is acceptable on
  ephemeral runners.
- Document the process/checklist for updating 1Password CLI versions and checksums.

---

## Operational Checklist (for maintainers)

- Before release:
  - [ ] Update the versions/checksums DB for the 1Password CLI when bumping.
  - [ ] Run integration tests on all supported platforms/architectures.
  - [ ] Verify GitHub masking is applied before writing outputs/env.

- During incident/bug triage:
  - [ ] Inspect audit/monitoring logs for context without secret values.
  - [ ] If unexpected plaintext ever appears, add or adjust scrubbing patterns and tests immediately.

- Security reviews:
  - [ ] Confirm that no new code paths print exceptions/raw tool outputs without sensitive-context logging.
  - [ ] Reassess deny-lists and validation bounds as the environment and attack surface evolves.

---

## Conclusion

The 1Password Secrets Action exhibits a strong security posture and high operational maturity. By addressing the small set of recommended improvements (primarily scrubbing breadth, a summary scrub pass, optional metadata redaction, and a more realistic `op` archive size ceiling), you can further reduce already-low risks and strengthen resilience. The action is production-ready.
