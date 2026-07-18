# `report` — homogeneous rendering

`report` renders a finding slice the same way for every tool. Product specifics (brand,
banner, tier labels, doc links, summary headline) are injected through `Options`; the
layout and severity palette are fixed so two tools look like siblings.

## Renderers

```go
func Banner(w io.Writer, opts Options)                                        // logo + tagline (usually stderr)
func Terminal(w io.Writer, opts Options, findings []finding.Finding, sum scoring.Summary)
func SARIF(w io.Writer, opts Options, source string, findings []finding.Finding) error // SARIF 2.1.0
func CSV(w io.Writer, findings []finding.Finding) error                       // one row per finding
func JUnit(w io.Writer, opts Options, findings []finding.Finding, total int) error     // JUnit XML
```

- **`Terminal`** — the rich human report: header (mode/source), a top-3 "immediate
  action" block, one detail block per control code (severity, tier, deviations,
  remediation, optional doc link), an optional controls table, and a severity summary.
  When there are no findings it prints a green "no deviations" line and the summary.
- **`SARIF`** — SARIF 2.1.0 for code-scanning back-ends. Each distinct `Code` becomes a
  `rule` (with `helpUri` if `DocURL` is set); each finding a `result` located on `source`.
  Severity maps to level: critical/high → `error`, medium → `warning`, else → `note`.
- **`CSV`** — `code,severity,subject,title,message,remediation`, header included.
- **`JUnit`** — one `<testsuite>`, one failing `<testcase>` per finding; `total` is the
  number of controls evaluated (passed + failed), so `tests`/`failures` are meaningful.

## `Options`

```go
type Options struct {
	ToolName string   // SARIF/JUnit tool name
	Version  string   // shown in banner and SARIF
	Mode     string   // header line, e.g. "live", "gitlab (API)"
	Source   string   // header line: audited source
	Banner   []string // ASCII logo (optional)
	Tagline  string   // line under the logo
	Brand    lipgloss.Color

	TierOf          func(finding.Finding) string // tier label, e.g. "R1·DOIT", "security" (nil ok)
	DocURL          func(finding.Finding) string // per-control doc link (nil ok)
	SummaryHeadline string                       // strong summary line, e.g. "Level reached: R3"
	HideTable       bool                         // omit the controls table (avoids duplication)
}
```

`TierOf` and `DocURL` are optional callbacks: a tool that has no tier concept or no doc
site just leaves them `nil`. `Brand` colours the banner and the "Summary" heading; the
severity colours (red/orange/amber/blue) are fixed so severity always reads the same.
