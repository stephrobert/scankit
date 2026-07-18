package scoring

import (
	"testing"

	"github.com/stephrobert/scankit/finding"
)

func TestSummarizeCounts(t *testing.T) {
	findings := []finding.Finding{
		{Code: "a", Severity: "critical"},
		{Code: "b", Severity: "high"},
		{Code: "c", Severity: "high"},
		{Code: "d", Severity: "low"},
	}
	s := Summarize(findings)
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
	if s.Counts["high"] != 2 {
		t.Errorf("Counts[high] = %d, want 2", s.Counts["high"])
	}
	if s.Counts["critical"] != 1 || s.Counts["low"] != 1 {
		t.Errorf("unexpected counts: %+v", s.Counts)
	}
}

func TestSummarizeDoitOpen(t *testing.T) {
	findings := []finding.Finding{
		{Code: "a", Severity: "high", Labels: map[string]string{"devoir": "DOIT", "niveau": "R1"}},
		{Code: "b", Severity: "low", Labels: map[string]string{"devoir": "DEVRAIT", "niveau": "R1"}},
		{Code: "c", Severity: "high", Labels: map[string]string{"devoir": "DOIT", "niveau": "R2"}},
	}
	s := Summarize(findings)
	if s.DoitOpen["R1"] != 1 {
		t.Errorf("DoitOpen[R1] = %d, want 1 (DEVRAIT must not count)", s.DoitOpen["R1"])
	}
	if s.DoitOpen["R2"] != 1 {
		t.Errorf("DoitOpen[R2] = %d, want 1", s.DoitOpen["R2"])
	}
}

func TestNiveauAtteint(t *testing.T) {
	cases := []struct {
		name string
		open map[string]int
		want string
	}{
		{"nothing open", map[string]int{}, "R3"},
		{"R1 open", map[string]int{"R1": 1}, "—"},
		{"R2 open", map[string]int{"R2": 2}, "R1"},
		{"R3 open", map[string]int{"R3": 1}, "R2"},
		{"R1 dominates", map[string]int{"R1": 1, "R3": 5}, "—"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NiveauAtteint(Summary{DoitOpen: c.open})
			if got != c.want {
				t.Errorf("NiveauAtteint(%v) = %q, want %q", c.open, got, c.want)
			}
		})
	}
}
