package report

import (
	"encoding/csv"
	"io"

	"github.com/stephrobert/scankit/finding"
)

// CSV émet les findings en CSV (une ligne par finding, en-tête inclus) pour
// tableur ou post-traitement dans une chaîne CI/CD.
func CSV(w io.Writer, findings []finding.Finding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"code", "severity", "subject", "title", "message", "remediation"}); err != nil {
		return err
	}
	for _, f := range findings {
		title := f.Title
		if title == "" {
			title = f.Message
		}
		if err := cw.Write([]string{f.Code, f.Severity, f.Subject, title, f.Message, f.Remediation}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
