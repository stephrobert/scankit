// Package engine encapsule le moteur OPA partagé : il charge les fichiers .rego
// trouvés dans une ou plusieurs fs.FS (politiques embarquées et/ou répertoires
// externes), découvre automatiquement les packages présents et agrège la règle
// `deny` de chacun en findings triés.
//
// Convention : chaque fichier .rego déclare `import rego.v1` et contribue à
// `deny contains f if { … }` où f porte les champs de finding.Finding. Aucune
// contrainte de nommage de package — l'engine interroge `<package>.deny` pour
// chaque package découvert, ce qui autorise aussi bien un package unique
// (style pepin : pepin.rules) que plusieurs (style pitstop : runner, runtime…).
package engine

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/stephrobert/scankit/finding"
)

// Evaluate compile toutes les politiques des sources contre input et retourne
// les findings agrégés et triés de façon déterministe.
func Evaluate(ctx context.Context, input any, sources ...fs.FS) ([]finding.Finding, error) {
	norm, err := normalize(input)
	if err != nil {
		return nil, fmt.Errorf("normalisation de l'entrée: %w", err)
	}

	modules, err := collectModules(sources...)
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, nil
	}

	queries, err := denyQueries(modules)
	if err != nil {
		return nil, err
	}

	// Modules communs à toutes les requêtes (compilés une fois par requête).
	base := make([]func(*rego.Rego), 0, len(modules)+2)
	for name, src := range modules {
		base = append(base, rego.Module(name, src))
	}
	base = append(base, rego.Input(norm))

	var findings []finding.Finding
	for _, q := range queries {
		opts := append(slices.Clone(base), rego.Query(q))
		rs, err := rego.New(opts...).Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("évaluation de %q: %w", q, err)
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			continue
		}
		raw, err := json.Marshal(rs[0].Expressions[0].Value)
		if err != nil {
			return nil, fmt.Errorf("sérialisation des findings: %w", err)
		}
		var batch []finding.Finding
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("désérialisation des findings: %w", err)
		}
		findings = append(findings, batch...)
	}

	slices.SortFunc(findings, compareFindings)
	return findings, nil
}

// collectModules parcourt chaque source et collecte les fichiers .rego (hors
// _test.rego), nommés de façon unique par index de source.
func collectModules(sources ...fs.FS) (map[string]string, error) {
	modules := make(map[string]string)
	for i, fsys := range sources {
		if fsys == nil {
			continue
		}
		err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".rego") || strings.HasSuffix(p, "_test.rego") {
				return nil
			}
			content, err := fs.ReadFile(fsys, p)
			if err != nil {
				return fmt.Errorf("lecture de %q: %w", p, err)
			}
			modules[fmt.Sprintf("src%d/%s", i, p)] = string(content)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("parcours des politiques: %w", err)
		}
	}
	return modules, nil
}

// denyQueries retourne, pour chaque package distinct présent dans les modules,
// la requête `<package>.deny` (ex. "data.pitstop.rules.deny"). Trié pour un
// ordre d'évaluation stable.
func denyQueries(modules map[string]string) ([]string, error) {
	seen := map[string]struct{}{}
	for name, src := range modules {
		m, err := ast.ParseModule(name, src)
		if err != nil {
			return nil, fmt.Errorf("analyse de %q: %w", name, err)
		}
		seen[m.Package.Path.String()] = struct{}{}
	}
	queries := make([]string, 0, len(seen))
	for pkg := range seen {
		queries = append(queries, pkg+".deny")
	}
	sort.Strings(queries)
	return queries, nil
}

func compareFindings(a, b finding.Finding) int {
	return cmp.Or(
		cmp.Compare(finding.SeverityRank(a.Severity), finding.SeverityRank(b.Severity)),
		cmp.Compare(a.Code, b.Code),
		cmp.Compare(a.Subject, b.Subject),
		cmp.Compare(a.Message, b.Message),
	)
}

// normalize fait un aller-retour JSON pour qu'OPA reçoive des types standard.
func normalize(input any) (any, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
