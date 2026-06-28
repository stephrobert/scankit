// Package finding définit le modèle de finding partagé par les produits
// d'analyse OPA/Rego (pepin, pitstop). Cœur minimal commun + remédiation
// optionnelle + labels libres pour le spécifique produit (niveau, devoir,
// provider, règle, catégorie…), afin qu'un seul type serve tous les domaines.
package finding

// Finding est une violation émise par une politique Rego. Les politiques
// retournent un objet JSON dont les clés correspondent aux champs ci-dessous.
type Finding struct {
	Code        string            `json:"code"`                  // identifiant de contrôle (ex. "R-D2", "CLOUD-NET-001")
	Title       string            `json:"title,omitempty"`       // libellé stable du contrôle (optionnel ; sinon le message sert de titre)
	Severity    string            `json:"severity"`              // critical | high | medium | low
	Subject     string            `json:"subject"`               // objet fautif (runner, ressource…)
	Message     string            `json:"message"`               // texte lisible, actionnable
	Remediation string            `json:"remediation,omitempty"` // remédiation (optionnel)
	Labels      map[string]string `json:"labels,omitempty"`      // spécifique produit : niveau, devoir, provider, rule, category…
}

// Label retourne la valeur d'un label, ou "" s'il est absent.
func (f Finding) Label(key string) string {
	if f.Labels == nil {
		return ""
	}
	return f.Labels[key]
}

// SeverityRank ordonne les sévérités (critical d'abord) pour un tri stable.
func SeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
