package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/stephrobert/scankit/assessment"
)

func sampleAssessment() assessment.Assessment {
	return assessment.Assessment{
		Run: assessment.Run{
			Tool:      assessment.Component{Name: "pepin", Version: "1.2.3", Digest: "sha256:abc"},
			Ruleset:   assessment.Component{Name: "commonrules", Version: "2026.07", Digest: "sha256:def"},
			Target:    assessment.Target{ID: "org-123", Provider: "exoscale", Region: "ch-gva-2", Platform: "exoscale"},
			Timestamp: "2026-07-18T18:00:00Z",
			Source:    "live-api",
			Scope:     assessment.Scope{Included: []string{"objectstorage", "network"}, Excluded: []string{"kubernetes"}, Note: "SKS not in scope this run"},
		},
		Results: []assessment.Result{
			{Control: "objectstorage_bucket_public_access", Status: assessment.Fail, Severity: "high", Subject: "backups",
				Evidence:   assessment.Evidence{Attribute: "bucket ACL", Observed: "public-read", Expected: "private", Source: "api:GetBucketAcl"},
				References: []assessment.Reference{{Framework: "secnumcloud-3.2", ID: "19.1"}}},
			{Control: "network_sg_no_ingress_22", Status: assessment.Pass, Severity: "critical", Subject: "sg-1"},
			{Control: "kubernetes_api_private", Status: assessment.NotEvaluated, Subject: "sks"},
		},
	}
}

func TestOSCALValid(t *testing.T) {
	var buf bytes.Buffer
	if err := OSCAL(&buf, sampleAssessment()); err != nil {
		t.Fatalf("OSCAL error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("OSCAL is not valid JSON: %v", err)
	}
	ar, ok := doc["assessment-results"].(map[string]any)
	if !ok {
		t.Fatal("missing assessment-results root")
	}
	meta := ar["metadata"].(map[string]any)
	if meta["oscal-version"] != oscalVersion {
		t.Errorf("oscal-version = %v, want %s", meta["oscal-version"], oscalVersion)
	}
	// Provenance props must be present.
	out := buf.String()
	for _, want := range []string{"tool-digest", "ruleset-digest", "target-id", "scope-excluded", "source"} {
		if !strings.Contains(out, want) {
			t.Errorf("provenance prop %q missing from OSCAL", want)
		}
	}

	results := ar["results"].([]any)
	res0 := results[0].(map[string]any)
	// OSCAL 1.1.2 requires a description on every result AND every finding — its absence
	// is a schema-conformance break (assessment-results is invalid without it).
	if d, _ := res0["description"].(string); d == "" {
		t.Error("result is missing the required OSCAL description")
	}
	for i, f := range res0["findings"].([]any) {
		if d, _ := f.(map[string]any)["description"].(string); d == "" {
			t.Errorf("finding[%d] is missing the required OSCAL description", i)
		}
	}
	// reviewed-controls excludes the not-evaluated control (2 reviewed of 3 results).
	sel := res0["reviewed-controls"].(map[string]any)["control-selections"].([]any)[0].(map[string]any)
	if inc := sel["include-controls"].([]any); len(inc) != 2 {
		t.Errorf("reviewed-controls = %d, want 2 (not-evaluated excluded)", len(inc))
	}
	// observations: one per result (3).
	if obs := res0["observations"].([]any); len(obs) != 3 {
		t.Errorf("observations = %d, want 3", len(obs))
	}
	// findings: every non-pass result (fail + not-evaluated = 2).
	if f := res0["findings"].([]any); len(f) != 2 {
		t.Errorf("findings = %d, want 2", len(f))
	}
	// The exact normative reference must appear.
	if !strings.Contains(out, "19.1") || !strings.Contains(out, "secnumcloud-3.2") {
		t.Error("exact normative reference not emitted in OSCAL")
	}
}

func TestOSCALDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := OSCAL(&a, sampleAssessment()); err != nil {
		t.Fatal(err)
	}
	if err := OSCAL(&b, sampleAssessment()); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("OSCAL output is not deterministic for the same assessment")
	}
}

func TestOSCALObjectiveState(t *testing.T) {
	if objectiveState(assessment.Pass) != "satisfied" {
		t.Error("pass must map to satisfied")
	}
	for _, s := range []assessment.Status{assessment.Fail, assessment.NotApplicable, assessment.NotEvaluated, assessment.Error} {
		if objectiveState(s) != "not-satisfied" {
			t.Errorf("%s must map to not-satisfied", s)
		}
	}
}

// OSCAL must never panic, must stay valid JSON, and — since labels, framework ids and
// observed values are all caller data — every prop it emits must still satisfy the datatypes
// the OSCAL schema enforces. Checking JSON well-formedness alone would miss the failure that
// actually matters: a document a consumer cannot validate.
func FuzzOSCAL(f *testing.F) {
	f.Add("c1", "fail", "high", "subj", "obs", "exp", "19.1", "domain", "iam", "yes")
	f.Add("", "", "", "", "", "", "", "", "", "")
	f.Add("日本", "pass", "低", "資源", "値", "期待", "A.5.1", "домен", "значение", "unknown")
	f.Add("c2", "pass", "low", "s", "line\nbreak", "e", "1.1", "3 numeric", "v", "na")
	f.Fuzz(func(t *testing.T, control, status, sev, subj, obs, exp, ref, labelKey, labelValue, proves string) {
		a := assessment.Assessment{
			Run: assessment.Run{Tool: assessment.Component{Name: "fuzz"}, Timestamp: "2026-01-01T00:00:00Z"},
			Results: []assessment.Result{{
				Control: control, Status: assessment.Status(status), Severity: sev, Subject: subj,
				Evidence:   assessment.Evidence{Observed: obs, Expected: exp, Proves: [3]string{proves, proves, proves}},
				References: []assessment.Reference{{Framework: "x", ID: ref}},
				Labels:     map[string]string{labelKey: labelValue},
			}},
		}
		var buf bytes.Buffer
		if err := OSCAL(&buf, a); err != nil {
			t.Fatalf("OSCAL error on fuzzed input: %v", err)
		}
		var v any
		if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
			t.Fatalf("OSCAL produced invalid JSON: %v", err)
		}
		checkPropDatatypes(t, v)
	})
}

// OSCAL datatypes, as the NIST 1.1.2 schema states them: TokenDatatype for a prop name and
// class, StringDatatype for its value.
var (
	oscalToken  = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}.\-_]*$`)
	oscalString = regexp.MustCompile(`^\S(.*\S)?$`)
)

// checkPropDatatypes walks the emitted document and asserts every prop it finds — wherever it
// sits: metadata, observation, finding or relevant-evidence — would pass schema validation.
func checkPropDatatypes(t *testing.T, node any) {
	t.Helper()
	switch n := node.(type) {
	case map[string]any:
		if name, ok := n["name"].(string); ok {
			if value, ok := n["value"].(string); ok {
				if !oscalToken.MatchString(name) {
					t.Errorf("prop name %q is not an OSCAL token", name)
				}
				if !oscalString.MatchString(value) {
					t.Errorf("prop value %q is empty, padded or multi-line", value)
				}
				if class, ok := n["class"].(string); ok && !oscalToken.MatchString(class) {
					t.Errorf("prop class %q is not an OSCAL token", class)
				}
			}
		}
		for _, v := range n {
			checkPropDatatypes(t, v)
		}
	case []any:
		for _, v := range n {
			checkPropDatatypes(t, v)
		}
	}
}

// pavoisResult mirrors what the main consumer fills: labels for its taxonomy and the
// running/persistent/reboot-survivable triple its "effective configuration" argument rests on.
func pavoisResult() assessment.Result {
	return assessment.Result{
		Control:  "sshd_permit_root_login",
		Title:    "SSH root login disabled",
		Status:   assessment.Pass,
		Severity: "high",
		Subject:  "sshd",
		Evidence: assessment.Evidence{
			Attribute: "PermitRootLogin",
			Observed:  "no",
			Expected:  "no",
			Source:    "command:sshd -T",
			Type:      "effective-runtime",
			Proves:    [3]string{"yes", "yes", "unknown"},
		},
		Labels: map[string]string{
			"domain":            "access-control",
			"remediation_class": "config",
			"ssg":               "rhel9",
			"anssi-bp028_level": "minimal",
		},
	}
}

// The richest data a consumer fills must reach the document: labels as namespaced props, and
// the evidence triple as relevant-evidence. Dropping either leaves an auditor unable to tell a
// control proven at runtime from one proven only in a config file.
func TestOSCALCarriesLabelsAndProves(t *testing.T) {
	a := sampleAssessment()
	a.Results = append(a.Results, pavoisResult())

	var buf bytes.Buffer
	if err := OSCAL(&buf, a); err != nil {
		t.Fatalf("OSCAL error: %v", err)
	}
	obs := observationFor(t, buf.Bytes(), "sshd_permit_root_login")

	// Labels: one prop each, keyed by class so a product label cannot shadow "status" & co.
	want := map[string]string{
		"domain":            "access-control",
		"remediation_class": "config",
		"ssg":               "rhel9",
		"anssi-bp028_level": "minimal",
	}
	got := map[string]string{}
	for _, p := range props(obs) {
		if p["name"] == "label" {
			got[p["class"]] = p["value"]
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %q = %q, want %q", k, got[k], v)
		}
	}

	// Proves: a relevant-evidence entry with one prop per dimension.
	rel, _ := obs["relevant-evidence"].([]any)
	if len(rel) != 1 {
		t.Fatalf("relevant-evidence entries = %d, want 1", len(rel))
	}
	entry := rel[0].(map[string]any)
	if d, _ := entry["description"].(string); d == "" {
		t.Error("relevant-evidence is missing the description OSCAL requires")
	}
	proven := map[string]string{}
	for _, p := range props(entry) {
		proven[p["name"]] = p["value"]
	}
	for name, value := range map[string]string{
		"proves-running":           "yes",
		"proves-persistent":        "yes",
		"proves-reboot-survivable": "unknown",
	} {
		if proven[name] != value {
			t.Errorf("%s = %q, want %q", name, proven[name], value)
		}
	}
}

// A result with no Proves must not emit an empty relevant-evidence array: the schema requires
// at least one entry, so emitting one would make the document invalid rather than empty.
func TestOSCALOmitsEmptyRelevantEvidence(t *testing.T) {
	var buf bytes.Buffer
	if err := OSCAL(&buf, sampleAssessment()); err != nil {
		t.Fatalf("OSCAL error: %v", err)
	}
	obs := observationFor(t, buf.Bytes(), "objectstorage_bucket_public_access")
	if _, present := obs["relevant-evidence"]; present {
		t.Error("relevant-evidence emitted for a result with no Proves")
	}
}

// Labels and framework ids are caller data. OSCAL requires NCNames for prop name/class and a
// non-empty single-line value, so anything else must be coerced or dropped — never published
// as-is, which would make the whole document unparseable for a consumer.
func TestOSCALSanitizesCallerSuppliedProps(t *testing.T) {
	a := sampleAssessment()
	a.Results = append(a.Results, assessment.Result{
		Control: "weird_labels",
		Status:  assessment.Fail,
		Evidence: assessment.Evidence{
			Observed: "line one\nline two",
			Proves:   [3]string{"yes", "", ""},
		},
		Labels: map[string]string{
			"3 numeric start": "kept",
			"with/slash":      "kept",
			"empty":           "",
			"":                "dropped",
		},
	})

	var buf bytes.Buffer
	if err := OSCAL(&buf, a); err != nil {
		t.Fatalf("OSCAL error: %v", err)
	}
	obs := observationFor(t, buf.Bytes(), "weird_labels")

	ncname := regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}.\-_]*$`)
	oneLine := regexp.MustCompile(`^\S(.*\S)?$`)
	for _, p := range props(obs) {
		if !ncname.MatchString(p["name"]) {
			t.Errorf("prop name %q is not an NCName", p["name"])
		}
		if c := p["class"]; c != "" && !ncname.MatchString(c) {
			t.Errorf("prop class %q is not an NCName", c)
		}
		if !oneLine.MatchString(p["value"]) {
			t.Errorf("prop value %q is empty, padded or multi-line", p["value"])
		}
	}

	labels := 0
	for _, p := range props(obs) {
		if p["name"] == "label" {
			labels++
		}
	}
	if labels != 2 { // the two with a usable key AND a non-empty value
		t.Errorf("emitted %d labels, want 2 (empty value and empty key dropped)", labels)
	}
}

// props flattens the string fields of an OSCAL props array for assertions.
func props(container map[string]any) []map[string]string {
	raw, _ := container["props"].([]any)
	out := make([]map[string]string, 0, len(raw))
	for _, p := range raw {
		m, _ := p.(map[string]any)
		flat := map[string]string{}
		for k, v := range m {
			s, _ := v.(string)
			flat[k] = s
		}
		out = append(out, flat)
	}
	return out
}

// observationFor returns the observation titled with the given control.
func observationFor(t *testing.T, doc []byte, control string) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("OSCAL is not valid JSON: %v", err)
	}
	ar := parsed["assessment-results"].(map[string]any)
	res := ar["results"].([]any)[0].(map[string]any)
	for _, o := range res["observations"].([]any) {
		obs := o.(map[string]any)
		if obs["title"] == control {
			return obs
		}
	}
	t.Fatalf("no observation for control %q", control)
	return nil
}
