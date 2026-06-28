package report

import (
	"encoding/xml"
	"io"

	"github.com/stephrobert/scankit/finding"
)

// JUnit émet un rapport JUnit XML (une testsuite, un testcase en échec par
// finding) consommable par les chaînes CI/CD (GitLab, Jenkins, GitHub Actions).
// `total` = nombre de contrôles évalués (réussis + échoués) ; failures = findings.
func JUnit(w io.Writer, opts Options, findings []finding.Finding, total int) error {
	type failure struct {
		Message string `xml:"message,attr"`
		Type    string `xml:"type,attr"`
		Body    string `xml:",chardata"`
	}
	type testcase struct {
		Name      string   `xml:"name,attr"`
		Classname string   `xml:"classname,attr"`
		Failure   *failure `xml:"failure,omitempty"`
	}
	type testsuite struct {
		XMLName  xml.Name   `xml:"testsuite"`
		Name     string     `xml:"name,attr"`
		Tests    int        `xml:"tests,attr"`
		Failures int        `xml:"failures,attr"`
		Cases    []testcase `xml:"testcase"`
	}

	name := opts.ToolName
	if name == "" {
		name = "scankit"
	}
	ts := testsuite{Name: name, Tests: total, Failures: len(findings)}
	for _, f := range findings {
		title := f.Title
		if title == "" {
			title = f.Message
		}
		body := f.Message
		if f.Remediation != "" {
			body += "\n\n" + f.Remediation
		}
		ts.Cases = append(ts.Cases, testcase{
			Name:      f.Code + " — " + title,
			Classname: f.Label("domain"),
			Failure:   &failure{Message: f.Message, Type: f.Severity, Body: body},
		})
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(ts); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
