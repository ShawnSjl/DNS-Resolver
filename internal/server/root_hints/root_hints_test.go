package root_hints

import (
	"context"
	"log"
	"testing"
)

func TestRootHints(t *testing.T) {
	ctx := context.Background()
	ns, a, aaaa, err := FetchRootHints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, nsRr := range ns {
		log.Println(nsRr.String())
	}
	for _, aRr := range a {
		log.Println(aRr.String())
	}
	for _, aaaaRr := range aaaa {
		log.Println(aaaaRr.String())
	}
	if len(ns) != 13 || len(a) != 13 || len(aaaa) != 13 {
		t.Fatal("expected 13 root hints")
	}
}
