# scankit

**Shared engine, findings, scoring and reporting for OPA/Rego security scanners.**

[![Go](https://github.com/stephrobert/scankit/actions/workflows/go.yml/badge.svg)](https://github.com/stephrobert/scankit/actions/workflows/go.yml)
[![CodeQL](https://github.com/stephrobert/scankit/actions/workflows/codeql.yml/badge.svg)](https://github.com/stephrobert/scankit/actions/workflows/codeql.yml)
[![Scorecard](https://github.com/stephrobert/scankit/actions/workflows/scorecard.yml/badge.svg)](https://github.com/stephrobert/scankit/actions/workflows/scorecard.yml)
[![Plumber](https://github.com/stephrobert/scankit/actions/workflows/plumber.yml/badge.svg)](https://github.com/stephrobert/scankit/actions/workflows/plumber.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/stephrobert/scankit/badge)](https://scorecard.dev/viewer/?uri=github.com/stephrobert/scankit)
[![Plumber Score](https://score.getplumber.io/github.com/stephrobert/scankit.svg)](https://score.getplumber.io/github.com/stephrobert/scankit)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/stephrobert/scankit.svg)](https://pkg.go.dev/github.com/stephrobert/scankit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

scankit is the small, focused Go library that a family of security scanners share so
they behave identically: **[pepin](https://github.com/stephrobert/pepin)** (multi-cloud
CSPM), **pitstop** (SCSL runner audit) and **[pavois](https://github.com/stephrobert/pavois)**
(Linux compliance). It gives them one Rego evaluation engine, one finding model, one
severity-scoring logic and one set of output renderers (rich terminal, SARIF, CSV,
JUnit). Product-specific concerns — brand, verdict wording, grade computation, the rules
themselves — stay in each product.

> If two scanners built on scankit disagree about how a finding looks, how a scan is
> scored, or how SARIF is emitted, that is a bug in scankit, not in the product.

## Why it exists

Writing a policy scanner means solving the same four problems every time: run Rego over
some input, model the violations, aggregate them, and print them. scankit solves each
once, so a new scanner is *just its rules and its collectors*.

## Packages

| Import path | Responsibility |
|---|---|
| [`engine`](docs/engine.md) | Load `.rego` from one or more `fs.FS`, auto-discover packages, aggregate each package's `deny` rule into sorted findings. |
| [`finding`](docs/finding.md) | The shared `Finding` type (code, severity, subject, message, remediation, free-form labels) and `SeverityRank`. |
| [`scoring`](docs/scoring.md) | Severity counters and the SCSL level verdict (`Summarize`, `NiveauAtteint`). Grade/score stays in the product. |
| [`assessment`](docs/assessment.md) | Opposable audit model: a per-control `Result` (typed status, evidence observed-vs-expected + source, exact normative references) and a `Run` provenance envelope. Bridges to `Finding`; renders to OSCAL. |
| [`report`](docs/report.md) | Homogeneous rendering: rich lipgloss `Terminal`, `SARIF` 2.1.0, `CSV`, `JUnit`, and `OSCAL` 1.1.2 assessment-results. Brand and tier labels injected via `Options`. |

## Install

```bash
go get github.com/stephrobert/scankit@latest
```

Requires Go 1.26+.

## Quick start

Evaluate an embedded Rego policy against some input and print the findings:

```go
package main

import (
	"context"
	"os"
	"testing/fstest"

	"github.com/stephrobert/scankit/engine"
	"github.com/stephrobert/scankit/report"
	"github.com/stephrobert/scankit/scoring"
)

func main() {
	policies := fstest.MapFS{
		"deny.rego": &fstest.MapFile{Data: []byte(`
package demo.rules
import rego.v1

deny contains f if {
	some r in input.resources
	r.public == true
	f := {
		"code":     "objectstorage_bucket_public_access",
		"severity": "high",
		"subject":  r.name,
		"message":  sprintf("%s: bucket is publicly readable", [r.name]),
	}
}`)},
	}

	input := map[string]any{"resources": []map[string]any{
		{"name": "backups", "public": true},
	}}

	findings, err := engine.Evaluate(context.Background(), input, policies)
	if err != nil {
		panic(err)
	}

	opts := report.Options{ToolName: "demo", Version: "0.1.0", Mode: "live", Source: "inventory.json"}
	report.Terminal(os.Stdout, opts, findings, scoring.Summarize(findings))
}
```

The same `findings` slice can be rendered as SARIF for code scanning, or JUnit/CSV for a
CI pipeline:

```go
report.SARIF(os.Stdout, opts, "inventory.json", findings) // SARIF 2.1.0
report.JUnit(os.Stdout, opts, findings, totalControls)    // JUnit XML
report.CSV(os.Stdout, findings)                           // CSV
```

## Design contract

- **Findings are plain data.** A Rego policy's `deny` set contains objects whose JSON
  keys map onto `finding.Finding`. scankit unmarshals them; it does not prescribe how
  you author them beyond the field names.
- **No package-naming constraint.** `engine.Evaluate` queries `<package>.deny` for every
  package it discovers, so a single-package product (pepin: `pepin.rules`) and a
  multi-package one (pitstop: `runner`, `runtime`, …) both work.
- **Determinism.** Findings are sorted by severity, then code, then subject, then
  message — a scan of the same input always renders identically.
- **Product specifics via `Options`.** Brand colour, ASCII banner, tier labels
  (`TierOf`), doc links (`DocURL`), summary headline — all injected, none hard-coded.

See [`docs/`](docs/) for a per-package guide, and
[pkg.go.dev](https://pkg.go.dev/github.com/stephrobert/scankit) for the full API.

## Consumers

- **pepin** — multi-cloud CSPM (`engine`, `finding`, `report`, `scoring`).
- **pavois** — Linux compliance scanner (`report`, `finding`, `scoring`).
- **pitstop** — SCSL runner audit (`engine`, `finding`, `report`, `scoring`).

## Contributing

Any change to the engine, finding model, scoring or rendering lands **here** so all
consumers benefit — never fork the behaviour into a product. Run `go test ./... -race`
and `go vet ./...` before opening a PR. See [CHANGELOG.md](CHANGELOG.md) for releases.

## License

[Apache License 2.0](LICENSE) © 2026 Stéphane Robert. See [NOTICE](NOTICE) for
third-party attributions.
