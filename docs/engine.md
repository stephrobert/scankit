# `engine` — the shared OPA/Rego engine

`engine.Evaluate` is the one place a scankit-based tool runs policy. It loads every
`.rego` file it finds across one or more `fs.FS`, discovers the packages present,
evaluates each package's `deny` rule against the input, and returns aggregated,
deterministically sorted findings.

## API

```go
func Evaluate(ctx context.Context, input any, sources ...fs.FS) ([]finding.Finding, error)
```

- **`input`** is any Go value; it is round-tripped through JSON so OPA receives standard
  types (`input.resources[...]`, etc.).
- **`sources`** are one or more `fs.FS`: an embedded policy set (`//go:embed`), an
  external `--policy-dir`, or both — they are merged. `nil` sources are skipped.
- Returns `nil, nil` when no modules are found (not an error).

## How it works

1. **Collect modules.** Walk each source, read every `*.rego` except `*_test.rego`,
   keying them uniquely per source index (`src0/…`, `src1/…`) so identically named files
   from different sources never collide.
2. **Discover packages.** Parse each module and collect distinct package paths. For each,
   the query becomes `<package>.deny` (e.g. `data.pepin.rules.deny`,
   `data.pitstop.runner.deny`). Queries are sorted for a stable evaluation order.
3. **Evaluate.** Compile all modules once, then run each `deny` query with the normalized
   input. Each result's value is JSON-marshalled and unmarshalled into `[]finding.Finding`.
4. **Sort.** All findings are ordered by severity → code → subject → message.

## Policy conventions

Each `.rego` file should:

```rego
package <yourtool>.rules   # any package name; multiple packages are fine
import rego.v1

deny contains f if {
	# … condition on input …
	f := {
		"code":     "…",
		"severity": "high",
		"subject":  "…",
		"message":  "…",
		# optional: "title", "remediation", "labels": {...}
	}
}
```

No naming constraint is imposed: a single-package product and a multi-package product
both work, because the engine queries `deny` for **every** package it discovers.

## Testing policies

Rego unit tests (`*_test.rego`) are ignored by the engine at scan time, so keep them
alongside the rules and run them with `opa test`. To test the Go integration, back the
`fs.FS` with `testing/fstest.MapFS` — no files on disk required (see the README quick
start).
