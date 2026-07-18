package report

import (
	"bytes"
	"encoding/json"
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

// OSCAL must never panic and must stay valid JSON for arbitrary result fields.
func FuzzOSCAL(f *testing.F) {
	f.Add("c1", "fail", "high", "subj", "obs", "exp", "19.1")
	f.Add("", "", "", "", "", "", "")
	f.Add("日本", "pass", "低", "資源", "値", "期待", "A.5.1")
	f.Fuzz(func(t *testing.T, control, status, sev, subj, obs, exp, ref string) {
		a := assessment.Assessment{
			Run: assessment.Run{Tool: assessment.Component{Name: "fuzz"}, Timestamp: "2026-01-01T00:00:00Z"},
			Results: []assessment.Result{{
				Control: control, Status: assessment.Status(status), Severity: sev, Subject: subj,
				Evidence:   assessment.Evidence{Observed: obs, Expected: exp},
				References: []assessment.Reference{{Framework: "x", ID: ref}},
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
	})
}
