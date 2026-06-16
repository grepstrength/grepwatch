package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/grepstrength/grepwatch/model"
)
//NuGet runs its search on Azure Search
const nugetSearchURL = "https://azuresearch-usnc.nuget.org/query?take=100&sortBy=lastEdited&prerelease=false" 

type nugetResponse struct {
	Data []nugetPackage `json:"data"`
}

type nugetPackage struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type nugetCrawler struct{}

//this is almost identical to cargo and maven, thankfully
func (nu nugetCrawler) FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nugetSearchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("nuget: build request: %w", err)
	}

	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nuget: fetch search: %w", err)
	}
	defer resp.Body.Close()

	var result nugetResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nuget: decode search: %w", err)
	}

	pkgs := make([]model.Package, 0, len(result.Data))
	for _, p := range result.Data {
		pkgs = append(pkgs, model.Package{
			Ecosystem: model.EcosystemNuGet,
			Name:      p.ID,
			Version:   p.Version,
		})
	}

	return pkgs, nil
}


func init() {
	Register("nuget", nugetCrawler{})
}