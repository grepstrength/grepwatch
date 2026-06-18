package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	ecosystemsBase = "https://packages.ecosyste.ms/api/v1"
	perPage        = 100              // ecosyste.ms page size; 10 pages -> 1000
	targetCount    = 1000             // how many names we want per ecosystem
	contactEnvVar  = "GREPWATCH_CONTACT_EMAIL" //put your real email in an environment variable
)

//source ties an ecosystems registry slug into the allowlist file its matching water loads at the startup
type source struct {
	label		string //for long lines
	registry	string //ecosyste.ms registry slug
	outFile		string //the path the watcher reads via loadList()
}

var sources = []source{
	{"npm", "npmjs.org", "data/npm.json"},
	{"pypi", "pypi.org", "data/pypi.json"},
	{"go", "proxy.golang.org", "data/go.json"},
	{"cargo", "crates.io", "data/cargo.json"},
	{"maven", "repo1.maven.org", "data/maven.json"},
	{"nuget", "nuget.org", "data/nuget.json"},
}

type ecosystemsPackage struct { //the ONLY field we pull from each ver large package object
	Name string `json:"name"`
}

func main() {
	contactEmail := os.Getenv(contactEnvVar)
	if contactEmail == "" {
		log.Fatalf("set %s to a contact email before running (ecosyste.ms's polite pool needs it to clear the 402)", contactEnvVar)
	}
	ctx := context.Background()
	client := &http.Client{Timeout: 30 * time.Second}
	for _, s := range sources {
		log.Printf("fetching top %d for %s (%s)", targetCount, s.label, s.registry)

		names, err := fetchTopNames(ctx, client, s.registry, targetCount, contactEmail)
		if err != nil {
			log.Printf("  %s failed: %v (skipping)", s.label, err)
			continue
		}

		if err := writeList(s.outFile, names); err != nil {
			log.Printf("  write %s failed: %v", s.outFile, err)
			continue
		}
		log.Printf("  wrote %d names to %s", len(names), s.outFile)
	}
}

//this owns paging and deduplication
func fetchTopNames(ctx context.Context, client *http.Client, registry string, limit int, contactEmail string) ([]string, error) {
	seen := make(map[string]bool)
	names := make([]string, 0, limit)
	for page := 1; len(names) < limit; page++ {
	batch, err := fetchPage(ctx, client, registry, page, contactEmail)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if len(batch) == 0 {
			break //registry has fewer than limit packages
		}
		for _, p := range batch {
			if p.Name == "" || seen[p.Name] {
				continue
			}
			seen[p.Name] = true
			names = append(names, p.Name)
			if len(names) == limit {
				break
			}
		}

		time.Sleep(250 * time.Millisecond) // genereous spacing
	}
	return names, nil
}

//fetchPage is just one HTTP request with the From header being he line that opts into ecosystems' polite pool
//without this, any anon bulk liting returns 402s 
func fetchPage(ctx context.Context, client *http.Client, registry string, page int, contactEmail string) ([]ecosystemsPackage, error) {
	url := fmt.Sprintf(
		"%s/registries/%s/packages?sort=dependent_packages_count&order=desc&per_page=%d&page=%d",
		ecosystemsBase, registry, perPage, page,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "grepWatch-genlists/1.0 (https://grepwatch.com)") //as always, replace with your own site and user agent string

	req.Header.Set("From", contactEmail)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var pkgs []ecosystemsPackage
	if err := json.NewDecoder(resp.Body).Decode(&pkgs); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return pkgs, nil
}
//seriealizes the exact string slice JSON the watchers wil
func writeList(path string, names []string) error {
	data, err := json.MarshalIndent(names, "", " ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n') //trailing newline keeps git diffs clean
	if err := os.WriteFile(path, data, 0o664); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}


