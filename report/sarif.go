package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/stephrobert/scankit/finding"
)

// Structures SARIF 2.1.0 (sous-ensemble nécessaire).
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// SARIF écrit un rapport SARIF 2.1.0. Chaque code distinct devient une « rule »
// (sa description courte inclut le tier si Options.TierOf le fournit) ; chaque
// finding, un « result » localisé sur la source auditée.
func SARIF(w io.Writer, opts Options, source string, findings []finding.Finding) error {
	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		if _, seen := rulesByID[f.Code]; !seen {
			desc := f.Code
			if t := tierOf(opts, f); t != "" {
				desc = fmt.Sprintf("%s (%s)", f.Code, t)
			}
			rule := sarifRule{ID: f.Code, ShortDescription: sarifText{Text: desc}}
			if opts.DocURL != nil {
				rule.HelpURI = opts.DocURL(f)
			}
			rulesByID[f.Code] = rule
		}
		results = append(results, sarifResult{
			RuleID:    f.Code,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: source}}}},
		})
	}

	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: opts.ToolName, Version: opts.Version, Rules: rules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encodage SARIF: %w", err)
	}
	return nil
}
