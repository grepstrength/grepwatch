package main

import (
	"context"
	"fmt"
	"log"

	"github.com/grepstrength/grepwatch/model"
	"github.com/grepstrength/grepwatch/watcher"
)

type fakeStore struct {
	versions map[string]string
}

func (f *fakeStore) key(eco model.Ecosystem, name string) string {
	return string(eco) + ":" + name
}

func (f *fakeStore) GetLastVersion(ctx context.Context, eco model.Ecosystem, name string) (string, error) {
	return f.versions[f.key(eco, name)], nil
}

func (f *fakeStore) SetLastVersion(ctx context.Context, eco model.Ecosystem, name, version string) error {
	f.versions[f.key(eco, name)] = version
	return nil
}

func main() {
	w, ok := watcher.Registry[model.EcosystemNPM]
	if !ok {
		log.Fatal("no npm watcher registered")
	}

	store := &fakeStore{versions: map[string]string{}}

	fmt.Println("=== First check (cold store, expect 0 results) ===")
	first, err := w.Check(context.Background(), store)
	if err != nil {
		log.Fatalf("first check failed: %v", err)
	}
	fmt.Printf("Resolved packages: %d\n", len(first))
	fmt.Printf("Baselines recorded: %d\n\n", len(store.versions))

	store.versions["npm:express"] = "4.0.0"
	fmt.Println("=== Second check (express forced stale, expect >=1 result) ===")
	second, err := w.Check(context.Background(), store)
	if err != nil {
		log.Fatalf("second check failed: %v", err)
	}
	fmt.Printf("Resolved packages: %d\n", len(second))
	for _, rp := range second {
		fmt.Printf("\n  Package:      %s@%s\n", rp.Package.Name, rp.Package.Version)
		fmt.Printf("  Source URL:   %s\n", rp.SourceURL)
		fmt.Printf("  Prev version: %s\n", rp.PrevVersion)
		fmt.Printf("  Prev URL:     %s\n", rp.PrevSourceURL)
	}
}