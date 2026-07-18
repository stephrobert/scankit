package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stephrobert/scankit/finding"
	"github.com/stephrobert/scankit/scoring"
)

func sample() []finding.Finding {
	return []finding.Finding{
		{Code: "network_wide_open", Severity: "critical", Subject: "sg-1", Message: "sg-1 : 0.0.0.0/0 ingress on 22", Remediation: "Restrict the source range."},
		{Code: "bucket_public", Severity: "high", Subject: "backups", Message: "backups : bucket is publicly readable"},
	}
}

func TestTerminalNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, Options{Mode: "live", Source: "inv.json", Brand: colOK}, nil, scoring.Summary{Counts: map[string]int{}}); err != nil {
		t.Fatalf("Terminal error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No deviations") {
		t.Errorf("expected clean-scan line, got:\n%s", out)
	}
}

func TestTerminalWithFindings(t *testing.T) {
	var buf bytes.Buffer
	findings := sample()
	if err := Terminal(&buf, Options{Mode: "live", Source: "inv.json"}, findings, scoring.Summarize(findings)); err != nil {
		t.Fatalf("Terminal error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"network_wide_open", "bucket_public", "Immediate action", "Summary", "Remediation"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
}

func TestSARIFValid(t *testing.T) {
	var buf bytes.Buffer
	findings := sample()
	if err := SARIF(&buf, Options{ToolName: "demo", Version: "0.1.0"}, "inv.json", findings); err != nil {
		t.Fatalf("SARIF error: %v", err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 2 {
		t.Fatalf("want 1 run / 2 results, got %+v", log.Runs)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("critical must map to error, got %q", log.Runs[0].Results[0].Level)
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, sample()); err != nil {
		t.Fatalf("CSV error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 { // header + 2 findings
		t.Fatalf("want 3 CSV lines, got %d: %q", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "code,severity,subject") {
		t.Errorf("unexpected CSV header: %q", lines[0])
	}
}

func TestJUnitValid(t *testing.T) {
	var buf bytes.Buffer
	findings := sample()
	if err := JUnit(&buf, Options{ToolName: "demo"}, findings, 10); err != nil {
		t.Fatalf("JUnit error: %v", err)
	}
	var ts struct {
		XMLName  xml.Name `xml:"testsuite"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Cases    []struct {
			Name string `xml:"name,attr"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &ts); err != nil {
		t.Fatalf("JUnit is not valid XML: %v", err)
	}
	if ts.Tests != 10 || ts.Failures != 2 {
		t.Errorf("tests=%d failures=%d, want 10/2", ts.Tests, ts.Failures)
	}
}

// Renderers must never panic on arbitrary finding fields (unicode, empty, huge).
func FuzzRenderers(f *testing.F) {
	f.Add("critical", "sg", "s : m", "R1·DOIT", "fix")
	f.Add("", "", "", "", "")
	f.Add("high", "日本語", "长长的消息 : détail", "tier", "remédiation")
	f.Fuzz(func(t *testing.T, sev, subject, message, tier, rem string) {
		findings := []finding.Finding{{Code: "c", Severity: sev, Subject: subject, Message: message, Remediation: rem}}
		opts := Options{ToolName: "fuzz", Version: "0", TierOf: func(finding.Finding) string { return tier }}
		var buf bytes.Buffer
		if err := Terminal(&buf, opts, findings, scoring.Summarize(findings)); err != nil {
			t.Fatalf("Terminal error on fuzzed input: %v", err)
		}
		buf.Reset()
		if err := SARIF(&buf, opts, "src", findings); err != nil {
			t.Fatalf("SARIF error on fuzzed input: %v", err)
		}
		buf.Reset()
		if err := CSV(&buf, findings); err != nil {
			t.Fatalf("CSV error on fuzzed input: %v", err)
		}
		buf.Reset()
		if err := JUnit(&buf, opts, findings, 1); err != nil {
			t.Fatalf("JUnit error on fuzzed input: %v", err)
		}
	})
}
