package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/grepstrength/grepwatch/model" 
)

const mavenSearchURL = "https://search.maven.org/solrsearch/select?q=*:*&rows=100&sort=timestamp+desc&wt=json" //Maven Central runs its searchon Solr... asking to give the most recent 100 pblished artifacts, newest first, as JSON

type mavenResponse struct {
	Response struct {
		Docs []mavenDoc `json:"docs"`
	} `json:"response"` //Solr nexts results under response.docs
}

type mavenDoc struct {
	GroupID    string `json:"g"`
	ArtifactID string `json:"a"`
	Version    string `json:"latestVersion"`
}
type mavenCrawler struct{}

//this is almost identical to cargo. 
func (m mavenCrawler) FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mavenSearchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("maven: build request: %w", err)
	}

	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maven: fetch search: %w", err)
	}
	defer resp.Body.Close()

	var result mavenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("maven: decode search: %w", err)
	}

	pkgs := make([]model.Package, 0, len(result.Response.Docs))
	for _, doc := range result.Response.Docs {
		name := doc.GroupID + ":" + doc.ArtifactID //this is the only real change to the cargo's FetchNew
		pkgs = append(pkgs, model.Package{
			Ecosystem: model.EcosystemMaven,
			Name:      name,
			Version:   doc.Version,
		})
	}

	return pkgs, nil
}

func init() {
	Register("maven", mavenCrawler{})
}