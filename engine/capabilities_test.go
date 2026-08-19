package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// Une politique externe est du code fourni par un tiers : les moteurs qui la
// chargent à chaud (pepin --policy-dir, pitstop) doivent lui refuser toute
// primitive réseau. Sans quoi une règle de quelques lignes exfiltre l'input
// évalué — inventaire cloud complet, user-data, documents de politique IAM —
// ou balaye le réseau interne du runner depuis l'intérieur du scanner.
//
// Ces tests portent sur le COMPORTEMENT (la règle s'évalue-t-elle ?), pas sur
// la forme de la liste de capacités : c'est la seule façon de prouver que le
// builtin est réellement hors d'atteinte.

// policyCalling construit une source contenant une règle deny qui appelle expr.
func policyCalling(expr string) fstest.MapFS {
	src := `package test.rules

import rego.v1

deny contains f if {
	x := ` + expr + `
	f := {
		"code":     "canary",
		"severity": "high",
		"subject":  "canary",
		"message":  sprintf("BUILTIN ATTEINT: %v", [x]),
	}
}
`
	return fstest.MapFS{"canary.rego": &fstest.MapFile{Data: []byte(src)}}
}

func TestNetworkBuiltinsAreDenied(t *testing.T) {
	// Un serveur réel : si le builtin passait, la requête arriverait ici. On veut
	// que le compilateur refuse AVANT tout appel, donc ce compteur doit rester à 0.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cases := []struct {
		name string
		expr string
	}{
		{"http.send", `http.send({"method": "POST", "url": "` + srv.URL + `", "body": input, "raise_error": false})`},
		{"net.lookup_ip_addr", `net.lookup_ip_addr("example.com")`},
		{"opa.runtime", `opa.runtime()`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Evaluate(context.Background(), map[string]any{"secret": "exfiltrable"}, policyCalling(tc.expr))
			if err == nil {
				t.Fatalf("%s reste appelable depuis une politique externe : la restriction de capacités est inopérante", tc.name)
			}
			// Le refus doit venir de la compilation (builtin inconnu), pas d'une
			// erreur d'exécution fortuite comme un réseau indisponible.
			if !strings.Contains(err.Error(), "undefined function") {
				t.Fatalf("%s : refus attendu à la compilation, obtenu %v", tc.name, err)
			}
		})
	}

	if hits != 0 {
		t.Fatalf("le serveur témoin a reçu %d requête(s) : une politique a joint le réseau", hits)
	}
}

// La restriction ne doit pas amputer le langage : les règles réelles de pepin et
// pitstop s'appuient sur ces builtins, qui n'ont aucune portée réseau.
func TestOrdinaryBuiltinsStillWork(t *testing.T) {
	src := `package test.rules

import rego.v1

deny contains f if {
	some r in input.resources
	r.type == "bucket"
	not object.get(r, ["attributes", "private"], false)
	f := {
		"code":     "objectstorage_bucket_public_access",
		"severity": "high",
		"subject":  sprintf("bucket/%s", [r.name]),
		"message":  concat(" ", ["bucket", r.name, "exposé"]),
		"labels":   {"provider": lower("Scaleway")},
	}
}
`
	fsys := fstest.MapFS{"rule.rego": &fstest.MapFile{Data: []byte(src)}}
	input := map[string]any{"resources": []any{
		map[string]any{"type": "bucket", "name": "backups", "attributes": map[string]any{}},
	}}

	got, err := Evaluate(context.Background(), input, fsys)
	if err != nil {
		t.Fatalf("une règle ordinaire ne doit pas être affectée par la restriction : %v", err)
	}
	if len(got) != 1 {
		b, _ := json.Marshal(got)
		t.Fatalf("attendu 1 finding, obtenu %d : %s", len(got), b)
	}
	if got[0].Subject != "bucket/backups" {
		t.Fatalf("subject inattendu : %q", got[0].Subject)
	}
}
