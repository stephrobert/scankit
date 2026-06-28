// Package report rend des findings de façon homogène pour les produits d'analyse
// (terminal riche façon Plumber/osc-policy, SARIF). Le spécifique produit (marque,
// libellé de « tier », ligne de synthèse) passe par Options, le reste est commun.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/stephrobert/scankit/finding"
	"github.com/stephrobert/scankit/scoring"
)

const hrWidth = 78

// Palette sévérité (fixe) ; la couleur de marque est paramétrable via Options.
var (
	colCritical = lipgloss.Color("#dc2626")
	colHigh     = lipgloss.Color("#f04438")
	colMedium   = lipgloss.Color("#fbbf24")
	colLow      = lipgloss.Color("#7ba0f0")
	colText     = lipgloss.Color("#f3f5f9")
	colMuted    = lipgloss.Color("#a3acbd")
	colRule     = lipgloss.Color("#69727f")
	colOK       = lipgloss.Color("#34d399")
)

var (
	stTitle = lipgloss.NewStyle().Foreground(colText).Bold(true)
	stValue = lipgloss.NewStyle().Foreground(colText)
	stMuted = lipgloss.NewStyle().Foreground(colMuted)
	stRule  = lipgloss.NewStyle().Foreground(colRule)
	stOK    = lipgloss.NewStyle().Foreground(colOK).Bold(true)
)

// Options porte le spécifique produit injecté dans le rendu.
type Options struct {
	ToolName string   // nom de l'outil (SARIF, ex. "pitstop")
	Version  string   // version du binaire (bandeau, SARIF)
	Mode     string   // libellé du mode (en-tête : "gitlab (API)", "live"…)
	Source   string   // source auditée (en-tête)
	Banner   []string // logo ASCII (optionnel)
	Tagline  string   // ligne sous le logo
	Brand    lipgloss.Color
	// TierOf rend l'étiquette de « tier » d'un finding (ex. "R1·DOIT", "security").
	// Peut être nil.
	TierOf func(finding.Finding) string
	// DocURL retourne le lien vers la doc (explication + remédiation) du contrôle
	// d'un finding — typiquement une page du référentiel SCSL. Peut être nil.
	DocURL func(finding.Finding) string
	// SummaryHeadline est la ligne forte du résumé (ex. "Niveau atteint : R3").
	SummaryHeadline string
	// HideTable : si vrai, le terminal n'affiche PAS la table récapitulative des
	// contrôles (Code|Contrôle|Sév|Tier|#) — elle fait doublon avec les blocs
	// détail. On garde top-3 + blocs détail + résumé. Défaut : table affichée
	// (comportement inchangé pour pitstop/plumber).
	HideTable bool
}

func sevColor(sev string) lipgloss.Color {
	switch sev {
	case "critical":
		return colCritical
	case "high":
		return colHigh
	case "medium":
		return colMedium
	case "low":
		return colLow
	}
	return colMuted
}

func sevIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	}
	return "⚪"
}

func shortSev(sev string) string {
	switch sev {
	case "critical":
		return "CRIT"
	case "high":
		return "HIGH"
	case "medium":
		return "MED "
	case "low":
		return "LOW "
	}
	return "INFO"
}

func tierOf(opts Options, f finding.Finding) string {
	if opts.TierOf == nil {
		return ""
	}
	return opts.TierOf(f)
}

// stripSubject retire le préfixe « <sujet> : » du message (le sujet est affiché
// à part) pour des lignes plus nettes.
func stripSubject(msg string) string {
	if i := strings.Index(msg, " : "); i >= 0 {
		return strings.TrimSpace(msg[i+3:])
	}
	return msg
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if lipgloss.Width(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Banner écrit le logo + la tagline (typiquement sur stderr).
func Banner(w io.Writer, opts Options) {
	brand := lipgloss.NewStyle().Foreground(opts.Brand).Bold(true)
	fmt.Fprintln(w)
	for _, l := range opts.Banner {
		fmt.Fprintln(w, " "+brand.Render(l))
	}
	if opts.Tagline != "" {
		fmt.Fprintln(w)
		tag := stMuted.Render("v"+opts.Version) + "  " + lipgloss.NewStyle().Foreground(colLow).Render("· "+opts.Tagline)
		fmt.Fprintln(w, " "+tag)
	}
	fmt.Fprintln(w)
}

// Terminal écrit le rapport humain complet.
func Terminal(w io.Writer, opts Options, findings []finding.Finding, sum scoring.Summary) {
	writeHeader(w, opts)
	if len(findings) == 0 {
		fmt.Fprintln(w, "  "+stOK.Render("✓")+" "+stValue.Render("No deviations found in the audited scope."))
		fmt.Fprintln(w)
		writeSummary(w, opts, sum)
		return
	}
	writeImmediateActions(w, findings)
	order, byCode := groupByCode(findings)
	for _, c := range order {
		writeCodeGroup(w, opts, byCode[c])
	}
	if !opts.HideTable {
		writeControlsTable(w, opts, order, byCode)
	}
	writeSummary(w, opts, sum)
}

func writeHeader(w io.Writer, opts Options) {
	bar := stRule.Render(strings.Repeat("─", hrWidth))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w, " "+stMuted.Render(fmt.Sprintf("%-8s", "Mode"))+"  "+stValue.Render(opts.Mode))
	fmt.Fprintln(w, " "+stMuted.Render(fmt.Sprintf("%-8s", "Source"))+"  "+stValue.Render(opts.Source))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w)
}

type codeGroup struct {
	Code     string
	Severity string
	Tier     string
	Title    string
	Findings []finding.Finding
}

// titleOf retourne le libellé de groupe : le titre stable du contrôle s'il est
// renseigné, sinon le message (sans le préfixe « <sujet> : ») en repli.
func titleOf(f finding.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return stripSubject(f.Message)
}

func groupByCode(findings []finding.Finding) ([]string, map[string]*codeGroup) {
	by := map[string]*codeGroup{}
	for _, f := range findings {
		g, ok := by[f.Code]
		if !ok {
			g = &codeGroup{Code: f.Code, Severity: f.Severity, Title: titleOf(f)}
			by[f.Code] = g
		}
		g.Findings = append(g.Findings, f)
	}
	order := make([]string, 0, len(by))
	for c := range by {
		order = append(order, c)
	}
	sort.SliceStable(order, func(i, j int) bool {
		si, sj := finding.SeverityRank(by[order[i]].Severity), finding.SeverityRank(by[order[j]].Severity)
		if si != sj {
			return si < sj
		}
		return order[i] < order[j]
	})
	return order, by
}

func writeCodeGroup(w io.Writer, opts Options, g *codeGroup) {
	sc := sevColor(g.Severity)
	bar := stRule.Render(strings.Repeat("─", hrWidth))
	sevTag := lipgloss.NewStyle().Foreground(sc).Bold(true).Render(strings.ToUpper(g.Severity))
	tier := tierOf(opts, g.Findings[0])

	fmt.Fprintln(w)
	fmt.Fprintln(w, bar)
	head := " " + sevTag + stMuted.Render("  ·  ") + lipgloss.NewStyle().Foreground(colLow).Render(g.Code)
	if tier != "" {
		head += stMuted.Render("  ·  ") + stMuted.Render(tier)
	}
	fmt.Fprintln(w, head)
	fmt.Fprintln(w, " "+stTitle.Render(truncate(g.Title, hrWidth-2)))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w, "  "+stMuted.Render("Total deviations:")+" "+lipgloss.NewStyle().Foreground(sc).Bold(true).Render(fmt.Sprintf("%d", len(g.Findings))))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+stMuted.Render("Details:"))
	for _, f := range g.Findings {
		sev := lipgloss.NewStyle().Foreground(sevColor(f.Severity)).Bold(true).Render(shortSev(f.Severity))
		fmt.Fprintf(w, "      %s  %s — %s\n", sev, stValue.Render(f.Subject), stValue.Render(stripSubject(f.Message)))
	}
	if rem := g.Findings[0].Remediation; rem != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  "+stMuted.Render("Remediation"))
		for _, l := range strings.Split(strings.TrimRight(rem, "\n"), "\n") {
			fmt.Fprintln(w, "    "+stValue.Render(l))
		}
	}
	if opts.DocURL != nil {
		if u := opts.DocURL(g.Findings[0]); u != "" {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  "+stMuted.Render("↳ docs: ")+lipgloss.NewStyle().Foreground(colLow).Render(u))
		}
	}
}

func writeControlsTable(w io.Writer, opts Options, order []string, byCode map[string]*codeGroup) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+stMuted.Render("Controls"))
	headers := []string{"Code", "Control", "Sev", "Tier", "#"}
	rows := make([][]string, 0, len(order))
	for _, c := range order {
		g := byCode[c]
		rows = append(rows, []string{
			g.Code,
			truncate(g.Title, 48),
			strings.ToUpper(g.Severity),
			tierOf(opts, g.Findings[0]),
			fmt.Sprintf("%d", len(g.Findings)),
		})
	}
	writeBoxTable(w, "  ", headers, rows, []bool{false, false, false, false, true})
}

func writeImmediateActions(w io.Writer, findings []finding.Finding) {
	sorted := make([]finding.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return finding.SeverityRank(sorted[i].Severity) < finding.SeverityRank(sorted[j].Severity)
	})
	top := sorted
	if len(top) > 3 {
		top = top[:3]
	}
	bar := stRule.Render(strings.Repeat("─", hrWidth))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w, " "+stTitle.Render(fmt.Sprintf("⚡ Immediate action — top %d most severe deviations", len(top))))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w)
	for i, f := range top {
		fmt.Fprintf(w, "  %d. %s %s  %s — %s\n", i+1, sevIcon(f.Severity), shortSev(f.Severity),
			lipgloss.NewStyle().Bold(true).Render(f.Code), truncate(stripSubject(f.Message), 64))
		fmt.Fprintf(w, "     %s %s\n", stMuted.Render("subject:"), f.Subject)
	}
	fmt.Fprintln(w)
}

func writeSummary(w io.Writer, opts Options, sum scoring.Summary) {
	bar := stRule.Render(strings.Repeat("─", hrWidth))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w, " "+lipgloss.NewStyle().Foreground(opts.Brand).Bold(true).Render("Summary"))
	fmt.Fprintln(w)
	if opts.SummaryHeadline != "" {
		fmt.Fprintln(w, " "+stValue.Render(opts.SummaryHeadline))
		fmt.Fprintln(w)
	}
	counts := fmt.Sprintf("🔴 CRITICAL %d   🟠 HIGH %d   🟡 MEDIUM %d   🔵 LOW %d",
		sum.Counts["critical"], sum.Counts["high"], sum.Counts["medium"], sum.Counts["low"])
	fmt.Fprintln(w, " "+counts)
	fmt.Fprintln(w, bar)
}

// writeBoxTable rend un tableau à bordures Unicode (╭─┬─╮ / ├─┼─┤ / ╰─┴─╯).
func writeBoxTable(w io.Writer, indent string, headers []string, rows [][]string, rightAlign []bool) {
	ncol := len(headers)
	widths := make([]int, ncol)
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < ncol {
				if n := lipgloss.Width(c); n > widths[i] {
					widths[i] = n
				}
			}
		}
	}
	pad := func(s string, i int) string {
		spaces := widths[i] - lipgloss.Width(s)
		if spaces < 0 {
			spaces = 0
		}
		if i < len(rightAlign) && rightAlign[i] {
			return strings.Repeat(" ", spaces) + s
		}
		return s + strings.Repeat(" ", spaces)
	}
	line := func(left, mid, right, fill string) string {
		parts := make([]string, ncol)
		for i, ww := range widths {
			parts[i] = strings.Repeat(fill, ww+2)
		}
		return indent + stRule.Render(left+strings.Join(parts, mid)+right)
	}
	row := func(cells []string) string {
		parts := make([]string, ncol)
		for i := 0; i < ncol; i++ {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			parts[i] = " " + pad(c, i) + " "
		}
		sep := stRule.Render("│")
		return indent + sep + strings.Join(parts, sep) + sep
	}
	fmt.Fprintln(w, line("╭", "┬", "╮", "─"))
	fmt.Fprintln(w, row(headers))
	fmt.Fprintln(w, line("├", "┼", "┤", "─"))
	for _, r := range rows {
		fmt.Fprintln(w, row(r))
	}
	fmt.Fprintln(w, line("╰", "┴", "╯", "─"))
}
