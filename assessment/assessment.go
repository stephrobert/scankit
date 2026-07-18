// Package assessment models an opposable audit outcome: per-control results with a typed
// status, effective evidence (observed vs expected + source), exact normative references,
// and a run-level provenance envelope (tool/ruleset digests, target, timestamp, source,
// scope).
//
// It complements finding.Finding — which represents only a failure — so a product can emit a
// full, auditor-defensible dossier: passes, not-applicable (justified) and not-evaluated
// count as much as failures, because "no finding" must never be confused with "compliant".
// An Assessment renders to OSCAL assessment-results (see report.OSCAL) for machine exchange,
// and its failing results bridge back to finding.Finding for the terminal/SARIF/CSV/JUnit
// renderers.
//
// scankit provides the shared model and renderers; each product populates the results from
// its own control catalogue and collectors, and keeps its own grade/verdict policy.
package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stephrobert/scankit/finding"
)

// Status is the outcome of evaluating one control against one subject.
type Status string

const (
	// Pass — the control was evaluated and the effective configuration satisfies it.
	Pass Status = "pass"
	// Fail — the control was evaluated and the effective configuration violates it.
	Fail Status = "fail"
	// NotApplicable — the control does not apply to this target (justify it, or an auditor
	// rejects it). E.g. the resource type is absent, or a structural gap makes it uncodable.
	NotApplicable Status = "not-applicable"
	// NotEvaluated — the control exists in the catalogue but was not assessed this run
	// (out of scope, collector missing). Distinguishing this from Pass is the whole point.
	NotEvaluated Status = "not-evaluated"
	// Error — evaluation failed technically (collection error, malformed input).
	Error Status = "error"
)

// Reference is an exact, versioned pointer to a requirement of a standard — the traceability
// an auditor needs. ID is the standard's own numbering, not an internal code.
type Reference struct {
	Framework string `json:"framework"`         // e.g. "secnumcloud-3.2", "anssi-bp028", "cis-v8", "iso-27001", "nist-800-53", "scsl"
	ID        string `json:"id"`                // e.g. "19.1", "R8", "6.7", "A.5.15", "CLD-IAM-1"
	Version   string `json:"version,omitempty"` // framework version if not encoded in Framework
}

// Evidence is the effective, observed proof behind a result: what was checked, what value was
// found versus what was required, and where the value came from. This is what makes a verdict
// reproducible and defensible rather than an opaque PASS/FAIL.
type Evidence struct {
	Attribute string    `json:"attribute,omitempty"` // the control point checked (e.g. "bucket ACL", "sysctl net.ipv4.ip_forward")
	Observed  string    `json:"observed,omitempty"`  // effective value collected
	Expected  string    `json:"expected,omitempty"`  // required value
	Source    string    `json:"source,omitempty"`    // provenance of the value, e.g. "api:GetBucketAcl", "terraform:planned_values", "command:sshd -T"
	Type      string    `json:"type,omitempty"`      // evidence type: effective-runtime | persistent-config | inventory-state | filesystem-state | behavioral | manual
	Proves    [3]string `json:"proves,omitempty"`    // what a pass proves: [running, persistent, reboot-survivable], each yes|unknown|na
}

// Waiver records an accepted risk with a written justification — distinct from NotApplicable
// (a waived control genuinely applies but is consciously accepted).
type Waiver struct {
	Justification string `json:"justification"`
	Until         string `json:"until,omitempty"` // RFC3339 expiry, optional
}

// Result is the outcome of one control against one subject, with the evidence and references
// that make it opposable.
type Result struct {
	Control     string            `json:"control"`               // agnostic control id (the shared identifier)
	Title       string            `json:"title,omitempty"`       // stable human label
	Status      Status            `json:"status"`                //
	Severity    string            `json:"severity,omitempty"`    // critical|high|medium|low
	Subject     string            `json:"subject,omitempty"`     // evaluated/offending resource
	Evidence    Evidence          `json:"evidence,omitzero"`     //
	References  []Reference       `json:"references,omitempty"`  // exact normative references
	Remediation string            `json:"remediation,omitempty"` //
	Waiver      *Waiver           `json:"waiver,omitempty"`      // accepted-risk justification (Status usually Fail)
	Labels      map[string]string `json:"labels,omitempty"`      // product specifics (provider, domain, level…)
}

// Message renders a human, actionable one-liner for a result, preferring an explicit
// expected-vs-observed statement when evidence is present.
func (r Result) Message() string {
	subj := r.Subject
	if subj == "" {
		subj = r.Control
	}
	e := r.Evidence
	switch {
	case e.Expected != "" && e.Observed != "":
		return fmt.Sprintf("%s: expected %s, observed %s", subj, e.Expected, e.Observed)
	case e.Observed != "":
		return fmt.Sprintf("%s: observed %s", subj, e.Observed)
	case r.Title != "":
		return fmt.Sprintf("%s: %s", subj, r.Title)
	default:
		return subj
	}
}

// Finding converts a failing Result to a finding.Finding for the terminal/SARIF/CSV/JUnit
// renderers. Non-failing results return the zero Finding and false, so callers can do:
//
//	if f, ok := r.Finding(); ok { findings = append(findings, f) }
func (r Result) Finding() (finding.Finding, bool) {
	if r.Status != Fail {
		return finding.Finding{}, false
	}
	labels := r.Labels
	if len(r.References) > 0 {
		labels = mergeRefs(labels, r.References)
	}
	return finding.Finding{
		Code:        r.Control,
		Title:       r.Title,
		Severity:    r.Severity,
		Subject:     r.Subject,
		Message:     r.Message(),
		Remediation: r.Remediation,
		Labels:      labels,
	}, true
}

// mergeRefs copies labels and adds one label per reference framework (framework -> "id[ ,id]")
// so the existing label-based renderers still surface the normative traceability.
func mergeRefs(labels map[string]string, refs []Reference) map[string]string {
	out := make(map[string]string, len(labels)+len(refs))
	for k, v := range labels {
		out[k] = v
	}
	byFw := map[string][]string{}
	order := []string{}
	for _, ref := range refs {
		if _, seen := byFw[ref.Framework]; !seen {
			order = append(order, ref.Framework)
		}
		byFw[ref.Framework] = append(byFw[ref.Framework], ref.ID)
	}
	for _, fw := range order {
		out[fw] = strings.Join(byFw[fw], ", ")
	}
	return out
}

// Component identifies the tool or ruleset that produced the assessment, with a content
// digest for integrity/non-repudiation.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"` // content hash, e.g. "sha256:…"
}

// Target identifies what was audited — the account/project/tenant, provider, region, platform.
type Target struct {
	ID       string `json:"id,omitempty"`
	Provider string `json:"provider,omitempty"`
	Region   string `json:"region,omitempty"`
	Platform string `json:"platform,omitempty"` // OS release or cloud family
}

// Scope attests what was and was not audited — required so an auditor can trust coverage.
type Scope struct {
	Included []string `json:"included,omitempty"` // resource types / domains covered
	Excluded []string `json:"excluded,omitempty"` // deliberately not covered
	Note     string   `json:"note,omitempty"`     // justification of exclusions
}

// Run is the provenance envelope of one assessment: who produced it, against what, when, from
// which source. Without it a result is not reproducible and not opposable.
type Run struct {
	Tool      Component `json:"tool"`
	Ruleset   Component `json:"ruleset"`
	Target    Target    `json:"target,omitzero"`
	Timestamp string    `json:"timestamp,omitempty"` // RFC3339 UTC — caller-stamped
	Source    string    `json:"source,omitempty"`    // "live-api" | "terraform-plan" | "s3" | "export"
	Scope     Scope     `json:"scope,omitzero"`
}

// Assessment is the full opposable dossier: the provenance of the run plus every control
// result (pass, fail, not-applicable, not-evaluated, error).
type Assessment struct {
	Run     Run      `json:"run"`
	Results []Result `json:"results"`
}

// Summary counts results by status.
type Summary struct {
	ByStatus map[Status]int `json:"by_status"`
	Total    int            `json:"total"`
}

// Summarize counts the results by status.
func (a Assessment) Summarize() Summary {
	s := Summary{ByStatus: map[Status]int{}, Total: len(a.Results)}
	for _, r := range a.Results {
		s.ByStatus[r.Status]++
	}
	return s
}

// Findings returns every failing result as a finding.Finding, sorted the same way the engine
// sorts (severity, then control, then subject), for the terminal/SARIF/CSV/JUnit renderers.
func (a Assessment) Findings() []finding.Finding {
	var out []finding.Finding
	for _, r := range a.Results {
		if f, ok := r.Finding(); ok {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if si, sj := finding.SeverityRank(out[i].Severity), finding.SeverityRank(out[j].Severity); si != sj {
			return si < sj
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// Conformant reports whether the assessment has zero failing results. Not-applicable,
// not-evaluated and waived-but-failing states are the caller's policy to weigh; this is the
// strict "no open deviation" reading.
func (a Assessment) Conformant() bool {
	for _, r := range a.Results {
		if r.Status == Fail {
			return false
		}
	}
	return true
}
