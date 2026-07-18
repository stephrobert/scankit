# `finding` — the shared finding model

`finding.Finding` is the single type every scankit-based tool speaks. A Rego policy
emits objects whose JSON keys map onto its fields; the engine unmarshals them; the
renderers consume them. One type serves every domain (cloud posture, Linux hardening,
CI runner audit) — domain specifics live in the free-form `Labels` map.

## Type

```go
type Finding struct {
	Code        string            `json:"code"`                  // control id, e.g. "objectstorage_bucket_public_access"
	Title       string            `json:"title,omitempty"`       // stable control label (falls back to Message)
	Severity    string            `json:"severity"`              // critical | high | medium | low
	Subject     string            `json:"subject"`               // offending object (resource, runner…)
	Message     string            `json:"message"`               // human-readable, actionable
	Remediation string            `json:"remediation,omitempty"` // how to fix (optional)
	Labels      map[string]string `json:"labels,omitempty"`      // product specifics: provider, category, niveau, devoir, domain…
}
```

## Field conventions

- **`Code`** is an agnostic control identifier, stable across releases and (in pepin)
  across providers. Renderers group findings by `Code`.
- **`Severity`** must be one of `critical | high | medium | low`. Any other value ranks
  last and renders as `INFO`/muted.
- **`Message`** may be prefixed with `"<subject> : "`; renderers strip that prefix since
  the subject is shown separately.
- **`Labels`** carry everything product-specific without widening the core type. Known
  keys read by scankit: `devoir`/`niveau` (scoring, SCSL DOIT requirements), `domain`
  (JUnit `classname`). Products add their own (`provider`, `category`, `rule`…).

## Helpers

```go
func (f Finding) Label(key string) string  // value or "" if absent (nil-safe)
func SeverityRank(severity string) int      // critical=0 … low=3, unknown=4 — for stable sorting
```

`SeverityRank` is the ordering used everywhere (engine sort, terminal grouping, immediate
-action top-N), so severities always appear most-critical-first.
