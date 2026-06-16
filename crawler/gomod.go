package crawler

import (
	"context"
	"encoding/json" //the Go module index serves newline-delimited JSON
	"fmt"
	"net/http"
	"time"

	"github.com/grepstrength/grepwatch/model"
)

const (
	goIndexURL = "https://index.golang.org/index" //chronological feed of every new module version published
	goProxyURL = "https://proxy.golang.org" //fetchs the actual module zip for diffing later
)
//each line in the field has these three fields
type goIndexEntry struct {
	Path      string    `json:"Path"`
	Version   string    `json:"Version"`
	Timestamp time.Time `json:"Timestamp"`
}

type goCrawler struct{}

func (g goCrawler) FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) {
	url := fmt.Sprintf("%s?since=%s", goIndexURL, since.UTC().Format(time.RFC3339))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("go: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go: fetch index: %w", err)
	}
	defer resp.Body.Close()

	var pkgs []model.Package
	decoder := json.NewDecoder(resp.Body)
	for decoder.More() { //the index feed isn't one JSON doc, but a sttream of separate JSON objects. we need to loop as long as there's another JSON value in the stream
		var entry goIndexEntry
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("go: decode entry: %w", err)
		}
		pkgs = append(pkgs, model.Package{
			Ecosystem: model.EcosystemGo,
			Name:      entry.Path,
			Version:   entry.Version,
		})
	}

	return pkgs, nil
}


func init() {
	Register("go", goCrawler{})
}