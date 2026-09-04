package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

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
			UUID:             obsUUID,
			Title:            r.Control,
			Description:      observationDesc(r),
			Methods:          []string{observationMethod(r)},
			Collected:        ts,
			Props:            evidenceProps(r),
			RelevantEvidence: relevantEvidence(r.Evidence),
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
				Props:               append(refProps(r.References), statusProps(r.Status)...),
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

// prop builds a namespaced property, or reports false when OSCAL would reject it. Both
// guards matter because names and values come from caller data: `name`/`class` must be XML
// NCNames and `value` a non-empty single-line string, so an unchecked label would publish a
// document no OSCAL consumer can validate — the one failure mode this export cannot recover
// from downstream.
func prop(name, class, value string) (oscalProp, bool) {
	n, v := ncName(name), propValue(value)
	if n == "" || v == "" {
		return oscalProp{}, false
	}
	return oscalProp{Name: n, Value: v, NS: oscalNS, Class: ncName(class)}, true
}

// ncName coerces s into an XML NCName (OSCAL's TokenDatatype): a letter or underscore, then
// letters, digits, '.', '-' or '_'. Anything else becomes '-'; a leading digit or punctuation
// gets an underscore in front. Returns "" for a string with nothing usable in it.
func ncName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || r == '_':
			b.WriteRune(r)
		case unicode.IsDigit(r) || r == '.' || r == '-':
			if b.Len() == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			if b.Len() == 0 {
				b.WriteByte('_')
			} else {
				b.WriteByte('-')
			}
		}
	}
	return b.String()
}

// propValue coerces s into OSCAL's StringDatatype: non-empty, no leading/trailing whitespace,
// and single-line (the schema's pattern does not match a newline). Line breaks become spaces
// rather than truncating the value: an auditor still reads what was observed.
func propValue(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func runProps(run assessment.Run) []oscalProp {
	p := []oscalProp{}
	add := func(name, val string) {
		if q, ok := prop(name, "", val); ok {
			p = append(p, q)
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
		add("scope-included", in)
	}
	for _, ex := range run.Scope.Excluded {
		add("scope-excluded", ex)
	}
	add("scope-note", run.Scope.Note)
	return p
}

func evidenceProps(r assessment.Result) []oscalProp {
	p := []oscalProp{}
	add := func(name, val string) {
		if q, ok := prop(name, "", val); ok {
			p = append(p, q)
		}
	}
	add("status", string(r.Status))
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
	return append(p, labelProps(r.Labels)...)
}

// labelProps carries Result.Labels — the product specifics a consumer fills (domain,
// remediation class, standard level…) — into the document instead of dropping them. The label
// key goes in `class`, not `name`, so a product label can never shadow a prop this package
// defines (status, severity, observed…). Sorted by key: the export is byte-reproducible.
func labelProps(labels map[string]string) []oscalProp {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	p := make([]oscalProp, 0, len(keys))
	for _, k := range keys {
		if q, ok := prop("label", k, labels[k]); ok && q.Class != "" {
			p = append(p, q)
		}
	}
	return p
}

// provesDimensions names what Evidence.Proves stores, in its order.
var provesDimensions = [3]string{"running", "persistent", "reboot-survivable"}

// relevantEvidence renders Evidence.Proves as an OSCAL relevant-evidence entry: the
// description states in words what a pass establishes, and one prop per dimension carries it
// in machine form. This is the distinction an auditor cannot otherwise make — a control
// proven at runtime versus one proven only in a config file — so it belongs in the evidence
// structure rather than lost among the observation's flat props.
//
// Emitted only when at least one dimension is filled: the schema requires a non-empty
// description and rejects an empty relevant-evidence array.
func relevantEvidence(e assessment.Evidence) []oscalRelEvidence {
	props := make([]oscalProp, 0, len(provesDimensions))
	stated := make([]string, 0, len(provesDimensions))
	for i, dim := range provesDimensions {
		q, ok := prop("proves-"+dim, "", e.Proves[i])
		if !ok {
			continue
		}
		props = append(props, q)
		stated = append(stated, dim+"="+q.Value)
	}
	if len(props) == 0 {
		return nil
	}
	desc := "A pass proves " + strings.Join(stated, ", ")
	if src := propValue(e.Source); src != "" {
		desc += "; collected from " + src
	}
	if typ := propValue(e.Type); typ != "" {
		desc += "; evidence type " + typ
	}
	return []oscalRelEvidence{{Description: desc + ".", Props: props}}
}

func refProps(refs []assessment.Reference) []oscalProp {
	p := make([]oscalProp, 0, len(refs))
	for _, ref := range refs {
		val := ref.ID
		if ref.Version != "" {
			val += " (" + ref.Version + ")"
		}
		if q, ok := prop("reference", ref.Framework, val); ok {
			p = append(p, q)
		}
	}
	return p
}

// statusProps returns the status property, or nothing when the status is empty — a caller can
// leave it unset, and a prop with an empty name and value is a document an OSCAL consumer
// rejects outright.
func statusProps(s assessment.Status) []oscalProp {
	if q, ok := prop("status", "", string(s)); ok {
		return []oscalProp{q}
	}
	return nil
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
	UUID             string             `json:"uuid"`
	Title            string             `json:"title,omitempty"`
	Description      string             `json:"description"`
	Methods          []string           `json:"methods"`
	Collected        string             `json:"collected,omitempty"`
	Props            []oscalProp        `json:"props,omitempty"`
	RelevantEvidence []oscalRelEvidence `json:"relevant-evidence,omitempty"`
}

type oscalRelEvidence struct {
	Description string      `json:"description"`
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
