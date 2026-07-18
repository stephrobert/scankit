package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/stephrobert/scankit/assessment"
)

// oscalVersion is the OSCAL schema version the emitted assessment-results conform to.
const oscalVersion = "1.1.2"

// oscalNS namespaces scankit-specific props so they don't collide with core OSCAL names.
const oscalNS = "https://github.com/stephrobert/scankit/ns/oscal"

// OSCAL writes an OSCAL 1.1.2 assessment-results document for an Assessment. Unlike an OSCAL
// catalog/profile (which publishes the standard), assessment-results ties a specific run to
// the controls: reviewed-controls lists what was assessed, observations carry the effective
// evidence, and findings record the not-satisfied objectives — the machine-exchange form of
// an opposable audit dossier. UUIDs are derived deterministically from content so the output
// is reproducible; timestamps come from the caller-stamped Run (no wall clock here).
func OSCAL(w io.Writer, a assessment.Assessment) error {
	ts := a.Run.Timestamp
	toolVer := a.Run.Tool.Version

	// Provenance carried as metadata props (tool + ruleset digests, target, source, scope).
	props := runProps(a.Run)

	reviewed := []oscalControlID{}
	observations := []oscalObservation{}
	findings := []oscalFinding{}

	// Stable order for reproducibility.
	results := append([]assessment.Result(nil), a.Results...)
	sort.SliceStable(results, func(i, j int) bool { return results[i].Control < results[j].Control })

	for _, r := range results {
		obsUUID := uuidFrom("obs", r.Control, r.Subject, string(r.Status))
		observations = append(observations, oscalObservation{
			UUID:        obsUUID,
			Title:       r.Control,
			Description: observationDesc(r),
			Methods:     []string{observationMethod(r)},
			Collected:   ts,
			Props:       evidenceProps(r),
		})

		// Controls actually reviewed (evaluated): pass/fail/not-applicable. Not-evaluated is
		// surfaced via its observation only — it was, by definition, not reviewed.
		if r.Status != assessment.NotEvaluated {
			reviewed = append(reviewed, oscalControlID{ControlID: r.Control})
		}

		// A finding records every objective that is not plainly satisfied.
		if r.Status != assessment.Pass {
			findings = append(findings, oscalFinding{
				UUID:        uuidFrom("finding", r.Control, r.Subject, string(r.Status)),
				Title:       findingTitle(r),
				Description: observationDesc(r), // required by OSCAL: a human-readable finding description
				Target: oscalTarget{
					Type:     "objective-id",
					TargetID: r.Control,
					Status:   oscalObjStatus{State: objectiveState(r.Status), Reason: string(r.Status)},
				},
				Props:               append(refProps(r.References), statusProp(r.Status)),
				RelatedObservations: []oscalRelObs{{ObservationUUID: obsUUID}},
			})
		}
	}

	doc := oscalDoc{AR: oscalAR{
		UUID: uuidFrom("assessment-results", a.Run.Target.ID, ts),
		Metadata: oscalMeta{
			Title:        assessmentTitle(a.Run),
			LastModified: ts,
			Version:      nonEmpty(toolVer, "0.0.0"),
			OscalVersion: oscalVersion,
			Props:        props,
		},
		ImportAP: oscalImportAP{Href: "#"},
		Results: []oscalResult{{
			UUID:             uuidFrom("result", a.Run.Target.ID, ts),
			Title:            "scankit assessment",
			Description:      resultDescription(a.Run, len(reviewed), len(findings)),
			Start:            ts,
			ReviewedControls: oscalReviewed{ControlSelections: []oscalControlSel{{IncludeControls: reviewed}}},
			Observations:     observations,
			Findings:         findings,
		}},
	}}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encodage OSCAL assessment-results: %w", err)
	}
	return nil
}

func assessmentTitle(run assessment.Run) string {
	if run.Target.ID != "" {
		return fmt.Sprintf("%s assessment of %s", nonEmpty(run.Tool.Name, "scankit"), run.Target.ID)
	}
	return nonEmpty(run.Tool.Name, "scankit") + " assessment"
}

func observationMethod(r assessment.Result) string {
	if r.Status == assessment.NotEvaluated {
		return "NONE"
	}
	return "EXAMINE"
}

func observationDesc(r assessment.Result) string {
	if m := r.Message(); m != "" {
		return string(r.Status) + " — " + m
	}
	return string(r.Status) + " — " + r.Control
}

func findingTitle(r assessment.Result) string {
	if r.Title != "" {
		return r.Title
	}
	return r.Control
}

// resultDescription is the human-readable summary OSCAL requires on a result: what was
// assessed and the headline counts, so the dossier is self-describing.
func resultDescription(run assessment.Run, reviewed, findings int) string {
	return fmt.Sprintf("%s: %d controls reviewed, %d findings.", assessmentTitle(run), reviewed, findings)
}

// objectiveState maps a status to an OSCAL objective-status state. OSCAL defines only
// satisfied/not-satisfied; the precise scankit status is preserved in the `reason` and props.
func objectiveState(s assessment.Status) string {
	if s == assessment.Pass {
		return "satisfied"
	}
	return "not-satisfied"
}

func runProps(run assessment.Run) []oscalProp {
	p := []oscalProp{}
	add := func(name, val string) {
		if val != "" {
			p = append(p, oscalProp{Name: name, Value: val, NS: oscalNS})
		}
	}
	add("tool-name", run.Tool.Name)
	add("tool-version", run.Tool.Version)
	add("tool-digest", run.Tool.Digest)
	add("ruleset-name", run.Ruleset.Name)
	add("ruleset-version", run.Ruleset.Version)
	add("ruleset-digest", run.Ruleset.Digest)
	add("target-id", run.Target.ID)
	add("target-provider", run.Target.Provider)
	add("target-region", run.Target.Region)
	add("target-platform", run.Target.Platform)
	add("source", run.Source)
	for _, in := range run.Scope.Included {
		p = append(p, oscalProp{Name: "scope-included", Value: in, NS: oscalNS})
	}
	for _, ex := range run.Scope.Excluded {
		p = append(p, oscalProp{Name: "scope-excluded", Value: ex, NS: oscalNS})
	}
	add("scope-note", run.Scope.Note)
	return p
}

func evidenceProps(r assessment.Result) []oscalProp {
	p := []oscalProp{{Name: "status", Value: string(r.Status), NS: oscalNS}}
	add := func(name, val string) {
		if val != "" {
			p = append(p, oscalProp{Name: name, Value: val, NS: oscalNS})
		}
	}
	add("severity", r.Severity)
	add("subject", r.Subject)
	add("attribute", r.Evidence.Attribute)
	add("observed", r.Evidence.Observed)
	add("expected", r.Evidence.Expected)
	add("evidence-source", r.Evidence.Source)
	add("evidence-type", r.Evidence.Type)
	if r.Waiver != nil {
		add("waiver-justification", r.Waiver.Justification)
		add("waiver-until", r.Waiver.Until)
	}
	return p
}

func refProps(refs []assessment.Reference) []oscalProp {
	p := make([]oscalProp, 0, len(refs))
	for _, ref := range refs {
		val := ref.ID
		if ref.Version != "" {
			val += " (" + ref.Version + ")"
		}
		p = append(p, oscalProp{Name: "reference", Value: val, NS: oscalNS, Class: ref.Framework})
	}
	return p
}

func statusProp(s assessment.Status) oscalProp {
	return oscalProp{Name: "status", Value: string(s), NS: oscalNS}
}

func nonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// uuidFrom derives a deterministic RFC 4122 v5-style UUID from the given parts (SHA-256),
// so the same assessment always yields the same document — no randomness, no wall clock.
func uuidFrom(parts ...string) string {
	h := sha256.Sum256([]byte("scankit-oscal:" + join(parts)))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	hexs := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexs[0:8], hexs[8:12], hexs[12:16], hexs[16:20], hexs[20:32])
}

func join(parts []string) string {
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += "\x1f"
		}
		out += s
	}
	return out
}

// OSCAL 1.1.2 assessment-results — the subset scankit emits.
type oscalDoc struct {
	AR oscalAR `json:"assessment-results"`
}

type oscalAR struct {
	UUID     string        `json:"uuid"`
	Metadata oscalMeta     `json:"metadata"`
	ImportAP oscalImportAP `json:"import-ap"`
	Results  []oscalResult `json:"results"`
}

type oscalMeta struct {
	Title        string      `json:"title"`
	LastModified string      `json:"last-modified"`
	Version      string      `json:"version"`
	OscalVersion string      `json:"oscal-version"`
	Props        []oscalProp `json:"props,omitempty"`
}

type oscalImportAP struct {
	Href string `json:"href"`
}

type oscalResult struct {
	UUID             string             `json:"uuid"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	Start            string             `json:"start,omitempty"`
	ReviewedControls oscalReviewed      `json:"reviewed-controls"`
	Observations     []oscalObservation `json:"observations,omitempty"`
	Findings         []oscalFinding     `json:"findings,omitempty"`
}

type oscalReviewed struct {
	ControlSelections []oscalControlSel `json:"control-selections"`
}

type oscalControlSel struct {
	IncludeControls []oscalControlID `json:"include-controls,omitempty"`
}

type oscalControlID struct {
	ControlID string `json:"control-id"`
}

type oscalObservation struct {
	UUID        string      `json:"uuid"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description"`
	Methods     []string    `json:"methods"`
	Collected   string      `json:"collected,omitempty"`
	Props       []oscalProp `json:"props,omitempty"`
}

type oscalFinding struct {
	UUID                string        `json:"uuid"`
	Title               string        `json:"title"`
	Description         string        `json:"description"`
	Target              oscalTarget   `json:"target"`
	Props               []oscalProp   `json:"props,omitempty"`
	RelatedObservations []oscalRelObs `json:"related-observations,omitempty"`
}

type oscalTarget struct {
	Type     string         `json:"type"`
	TargetID string         `json:"target-id"`
	Status   oscalObjStatus `json:"status"`
}

type oscalObjStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type oscalRelObs struct {
	ObservationUUID string `json:"observation-uuid"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
	Class string `json:"class,omitempty"`
}
