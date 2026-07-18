package engine

import (
	"context"
	"encoding/json"
	"testing"
	"testing/fstest"

	"github.com/stephrobert/scankit/finding"
)

// policy that flags publicly-readable resources.
const publicPolicy = `package demo.rules
import rego.v1

deny contains f if {
	some r in input.resources
	object.get(r, "public", false) == true
	f := {
		"code":     "bucket_public",
		"severity": "high",
		"subject":  object.get(r, "name", "?"),
		"message":  "public resource",
	}
}`

// second package, distinct severity, to exercise multi-package discovery + sorting.
const critPolicy = `package demo.crit
import rego.v1

deny contains f if {
	some r in input.resources
	object.get(r, "wide_open", false) == true
	f := {
		"code":     "network_wide_open",
		"severity": "critical",
		"subject":  object.get(r, "name", "?"),
		"message":  "0.0.0.0/0 ingress",
	}
}`

func polFS() fstest.MapFS {
	return fstest.MapFS{
		"demo.rego":      &fstest.MapFile{Data: []byte(publicPolicy)},
		"crit.rego":      &fstest.MapFile{Data: []byte(critPolicy)},
		"demo_test.rego": &fstest.MapFile{Data: []byte("package demo.rules\n")}, // must be ignored
	}
}

func TestEvaluateNoSources(t *testing.T) {
	got, err := Evaluate(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil findings with no sources, got %v", got)
	}
}

func TestEvaluateSingleMatch(t *testing.T) {
	input := map[string]any{"resources": []map[string]any{
		{"name": "backups", "public": true},
		{"name": "logs", "public": false},
	}}
	got, err := Evaluate(context.Background(), input, polFS())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Code != "bucket_public" || got[0].Subject != "backups" {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

func TestEvaluateSortsBySeverityThenCode(t *testing.T) {
	input := map[string]any{"resources": []map[string]any{
		{"name": "sg-1", "public": true, "wide_open": true},
	}}
	got, err := Evaluate(context.Background(), input, polFS())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	if finding.SeverityRank(got[0].Severity) > finding.SeverityRank(got[1].Severity) {
		t.Errorf("findings not sorted by severity: %q then %q", got[0].Severity, got[1].Severity)
	}
	if got[0].Code != "network_wide_open" {
		t.Errorf("critical finding must come first, got %q", got[0].Code)
	}
}

func TestEvaluateDeterministic(t *testing.T) {
	input := map[string]any{"resources": []map[string]any{
		{"name": "a", "public": true},
		{"name": "b", "public": true},
	}}
	first, _ := Evaluate(context.Background(), input, polFS())
	second, _ := Evaluate(context.Background(), input, polFS())
	fj, _ := json.Marshal(first)
	sj, _ := json.Marshal(second)
	if string(fj) != string(sj) {
		t.Errorf("evaluation not deterministic:\n%s\n%s", fj, sj)
	}
}

func FuzzEvaluate(f *testing.F) {
	f.Add(`{"resources":[{"name":"x","public":true}]}`)
	f.Add(`{}`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Add(`{"resources":"not-an-array"}`)
	pol := polFS()
	f.Fuzz(func(t *testing.T, raw string) {
		var input any
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Skip() // only well-formed JSON reaches Evaluate in practice
		}
		// Must never panic on arbitrary (well-formed) input; errors are acceptable.
		if _, err := Evaluate(context.Background(), input, pol); err != nil {
			t.Skipf("evaluation error (acceptable): %v", err)
		}
	})
}
