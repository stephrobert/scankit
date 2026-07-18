package finding

import "testing"

func TestSeverityRank(t *testing.T) {
	cases := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"":         4,
		"bogus":    4,
	}
	for sev, want := range cases {
		if got := SeverityRank(sev); got != want {
			t.Errorf("SeverityRank(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestSeverityRankOrders(t *testing.T) {
	if SeverityRank("critical") >= SeverityRank("high") {
		t.Fatal("critical must rank before high")
	}
	if SeverityRank("low") >= SeverityRank("unknown") {
		t.Fatal("known severities must rank before unknown")
	}
}

func TestLabel(t *testing.T) {
	var zero Finding
	if got := zero.Label("provider"); got != "" {
		t.Errorf("Label on nil map = %q, want empty", got)
	}

	f := Finding{Labels: map[string]string{"provider": "exoscale"}}
	if got := f.Label("provider"); got != "exoscale" {
		t.Errorf("Label(provider) = %q, want exoscale", got)
	}
	if got := f.Label("absent"); got != "" {
		t.Errorf("Label(absent) = %q, want empty", got)
	}
}
