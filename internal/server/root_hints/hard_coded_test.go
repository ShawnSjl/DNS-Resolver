package root_hints

import (
	"log"
	"testing"
)

func TestHardCodedRootHints(t *testing.T) {
	ns, a, aaaa, when := getHardCodedRootHints()
	for _, nsRr := range ns {
		log.Println(nsRr.String())
	}
	for _, aRr := range a {
		log.Println(aRr.String())
	}
	for _, aaaaRr := range aaaa {
		log.Println(aaaaRr.String())
	}
	log.Println("Hard Coded Time: ", when.String())
	if len(ns) != 13 || len(a) != 13 || len(aaaa) != 13 {
		t.Fatal("expected 13 root hints")
	}
}
