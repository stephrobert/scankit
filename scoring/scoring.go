// Package scoring agrège des compteurs par sévérité. Le calcul du niveau/grade
// (R1/R2/R3 pour pitstop, A-G/score pour pepin) reste spécifique au produit :
// il lit les labels des findings et fournit un libellé de synthèse au renderer.
package scoring

import "github.com/stephrobert/scankit/finding"

// Summary résume les findings d'un scan.
type Summary struct {
	Counts   map[string]int // nombre de findings par sévérité (critical/high/medium/low)
	Total    int            // total de findings
	DoitOpen map[string]int // exigences DOIT non satisfaites, par niveau (R1/R2/R3)
}

// Summarize compte les findings par sévérité et, à partir des labels « niveau »
// et « devoir », les exigences DOIT en écart par niveau (base du niveau atteint).
func Summarize(findings []finding.Finding) Summary {
	s := Summary{Counts: map[string]int{}, DoitOpen: map[string]int{}, Total: len(findings)}
	for _, f := range findings {
		s.Counts[f.Severity]++
		if f.Label("devoir") == "DOIT" {
			s.DoitOpen[f.Label("niveau")]++
		}
	}
	return s
}

// NiveauAtteint applique la logique des checklists SCSL : un niveau est atteint
// si toutes les exigences DOIT jusqu'à ce niveau sont satisfaites. Verdict de
// conformité canonique, piloté par le framework SCSL et partagé par les produits.
// Retourne "R1" | "R2" | "R3" | "—" (R1 non atteint).
func NiveauAtteint(s Summary) string {
	switch {
	case s.DoitOpen["R1"] > 0:
		return "—"
	case s.DoitOpen["R2"] > 0:
		return "R1"
	case s.DoitOpen["R3"] > 0:
		return "R2"
	default:
		return "R3"
	}
}
