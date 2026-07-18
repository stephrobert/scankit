# `assessment` — the opposable audit model

`finding.Finding` represents a **failure** only. An auditor needs more: which controls
**passed**, which are **not-applicable** (with justification), which were **not-evaluated**,
the **effective evidence** behind each verdict, the **exact normative references**, and the
**provenance** of the run. `assessment` adds that, so a product can emit a defensible dossier
— and render it as OSCAL for machine exchange — without confusing "no finding" with
"compliant".

scankit provides the shared model and renderers; each product populates the results from its
own control catalogue and collectors, and keeps its own grade/verdict policy.

## Types

```go
type Status string // "pass" | "fail" | "not-applicable" | "not-evaluated" | "error"

type Reference struct { Framework, ID, Version string } // exact, versioned: secnumcloud-3.2 §19.1, anssi-bp028 R8, cis-v8 6.7, iso-27001 A.5.15, scsl CLD-IAM-1

type Evidence struct {
	Attribute, Observed, Expected string // the control point, the effective value, the required value
	Source string                        // "api:GetBucketAcl" | "terraform:planned_values" | "command:sshd -T"
	Type   string                        // effective-runtime | persistent-config | inventory-state | ...
	Proves [3]string                     // what a pass proves: [running, persistent, reboot-survivable] = yes|unknown|na
}

type Result struct {
	Control     string
	Title       string
	Status      Status
	Severity    string
	Subject     string       // evaluated/offending resource
	Evidence    Evidence
	References  []Reference
	Remediation string
	Waiver      *Waiver       // accepted-risk justification (distinct from not-applicable)
	Labels      map[string]string
}

type Run struct {            // provenance / integrity envelope
	Tool, Ruleset Component   // name + version + Digest (content hash) — non-repudiation
	Target        Target      // account/project/tenant, provider, region, platform
	Timestamp     string      // RFC3339 UTC (caller-stamped)
	Source        string      // live-api | terraform-plan | s3 | export
	Scope         Scope       // included / excluded + justification — attests coverage
}

type Assessment struct { Run Run; Results []Result }
```

## Why each piece is opposable

- **Status beyond fail** — `pass` proves a control was evaluated *and* satisfied;
  `not-evaluated` is emitted explicitly so a gap can never masquerade as compliance;
  `not-applicable` carries a justification (an auditor rejects an unjustified N/A).
- **Evidence** — observed-vs-expected plus the `Source` makes a verdict reproducible: a third
  party can re-collect the same value and reach the same result.
- **Reference** — the standard's own numbering (not an internal code) is what an auditor
  traces; keep it exact and versioned.
- **Run** — tool/ruleset **digests**, target identity, timestamp and source are the minimum
  for a result to be attributable and reproducible.

## Bridges and renderers

```go
f, ok := result.Finding()            // a Fail becomes a finding.Finding (nil/false otherwise)
findings := assessment.Findings()    // all fails, sorted like the engine, for Terminal/SARIF/CSV/JUnit
sum := assessment.Summarize()        // counts by status
report.OSCAL(w, assessment)          // OSCAL 1.1.2 assessment-results (reviewed-controls + observations + findings)
```

`report.OSCAL` emits a deterministic OSCAL assessment-results document: `reviewed-controls`
lists what was assessed, `observations` carry the evidence, `findings` record every
not-satisfied objective, and the `Run` provenance is stamped into the metadata props. UUIDs
are derived from content (no randomness) and timestamps come from `Run.Timestamp`, so the same
assessment always yields the same document.

The grade (A–E), remediation taxonomy and product verdict stay in the product; `assessment`
is the shared, auditor-facing shape they all serialize to.
