# Changelog

All notable changes to scankit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stephrobert/scankit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/stephrobert/scankit/releases/tag/v0.1.0
