package assessment

import (
	"testing"

	"github.com/stephrobert/scankit/finding"
)

func sampleResults() []Result {
	return []Result{
		{Control: "objectstorage_bucket_public_access", Status: Fail, Severity: "high", Subject: "backups",
			Evidence:    Evidence{Attribute: "bucket ACL", Observed: "public-read", Expected: "private", Source: "api:GetBucketAcl", Type: "inventory-state"},
			References:  []Reference{{Framework: "secnumcloud-3.2", ID: "19.1"}, {Framework: "cis-v8", ID: "3.3"}},
			Remediation: "Set the bucket ACL to private."},
		{Control: "network_sg_no_ingress_22_from_internet", Status: Pass, Severity: "critical", Subject: "sg-1",
			Evidence: Evidence{Observed: "10.0.0.0/8", Expected: "no 0.0.0.0/0 on 22", Source: "api:ListSecurityGroups"}},
		{Control: "blockstorage_snapshot_not_shareable", Status: NotApplicable, Subject: "exoscale",
			Waiver: &Waiver{Justification: "Exoscale block snapshots are not shareable by construction."}},
		{Control: "kubernetes_api_private", Status: NotEvaluated, Subject: "sks"},
	}
}

func TestFindingBridge(t *testing.T) {
	fail := sampleResults()[0]
	f, ok := fail.Finding()
	if !ok {
		t.Fatal("a failing result must produce a Finding")
	}
	if f.Code != "objectstorage_bucket_public_access" || f.Severity != "high" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Message == "" || f.Remediation == "" {
		t.Error("finding should carry message + remediation")
	}
	// Normative references survive as labels for the existing renderers.
	if f.Label("secnumcloud-3.2") != "19.1" || f.Label("cis-v8") != "3.3" {
		t.Errorf("references not surfaced as labels: %v", f.Labels)
	}

	pass := sampleResults()[1]
	if _, ok := pass.Finding(); ok {
		t.Error("a passing result must NOT produce a Finding")
	}
}

func TestMessage(t *testing.T) {
	r := Result{Subject: "backups", Evidence: Evidence{Expected: "private", Observed: "public-read"}}
	want := "backups: expected private, observed public-read"
	if got := r.Message(); got != want {
		t.Errorf("Message = %q, want %q", got, want)
	}
	// Falls back to control id when no subject.
	r2 := Result{Control: "c1"}
	if got := r2.Message(); got != "c1" {
		t.Errorf("Message fallback = %q, want c1", got)
	}
}

func TestSummarize(t *testing.T) {
	a := Assessment{Results: sampleResults()}
	s := a.Summarize()
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
	for st, want := range map[Status]int{Fail: 1, Pass: 1, NotApplicable: 1, NotEvaluated: 1} {
		if s.ByStatus[st] != want {
			t.Errorf("ByStatus[%s] = %d, want %d", st, s.ByStatus[st], want)
		}
	}
}

func TestFindingsSortedAndFilteredToFails(t *testing.T) {
	a := Assessment{Results: append(sampleResults(), Result{Control: "aaa_crit", Status: Fail, Severity: "critical", Subject: "x"})}
	fs := a.Findings()
	if len(fs) != 2 { // only the two Fail results
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	// critical sorts before high.
	if finding.SeverityRank(fs[0].Severity) > finding.SeverityRank(fs[1].Severity) {
		t.Errorf("findings not sorted by severity: %q then %q", fs[0].Severity, fs[1].Severity)
	}
}

func TestConformant(t *testing.T) {
	if (Assessment{Results: sampleResults()}).Conformant() {
		t.Error("assessment with a Fail must not be conformant")
	}
	clean := []Result{{Control: "a", Status: Pass}, {Control: "b", Status: NotApplicable}}
	if !(Assessment{Results: clean}).Conformant() {
		t.Error("assessment with no Fail must be conformant")
	}
}
