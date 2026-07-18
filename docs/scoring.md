# `scoring` — severity aggregation and SCSL level verdict

`scoring` turns a slice of findings into counters and a compliance level. It deliberately
stops there: the product-facing **grade/score** (pepin's A–G, pavois's A–E) is computed
in each product from these counts, because the weighting is product policy.

## API

```go
type Summary struct {
	Counts   map[string]int // findings per severity (critical/high/medium/low)
	Total    int            // total findings
	DoitOpen map[string]int // unmet DOIT requirements per level (R1/R2/R3)
}

func Summarize(findings []finding.Finding) Summary
func NiveauAtteint(s Summary) string // "R1" | "R2" | "R3" | "—"
```

## `Summarize`

Counts findings by severity, and — reading the `devoir` and `niveau` labels — tallies the
unmet **DOIT** requirements per level. A finding contributes to `DoitOpen[niveau]` only
when its `devoir` label equals `"DOIT"`. Products that don't use SCSL levels simply leave
`DoitOpen` empty and use `Counts`/`Total`.

## `NiveauAtteint`

Applies the SCSL checklist rule: a level is reached only if every DOIT requirement up to
and including it is satisfied.

| Condition | Verdict |
|---|---|
| any DOIT open at R1 | `—` (R1 not reached) |
| any DOIT open at R2 | `R1` |
| any DOIT open at R3 | `R2` |
| all DOIT satisfied | `R3` |

This is the canonical conformity verdict shared by the SCSL-based tools; feed the result
into `report.Options.SummaryHeadline` to display it.
