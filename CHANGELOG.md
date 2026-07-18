# Changelog

All notable changes to scankit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stephrobert/scankit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/stephrobert/scankit/releases/tag/v0.2.0
[0.1.3]: https://github.com/stephrobert/scankit/releases/tag/v0.1.3
[0.1.0]: https://github.com/stephrobert/scankit/releases/tag/v0.1.0
