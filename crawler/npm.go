package crawler

import (
	"context"
	"encoding/json" //needed for decodding the registry reponse
	"fmt" //need to wrap errors with context
	"net/http"
	"time"

	"github.com/grepstrength/grepwatch/model"
)

//muy importante line... 
//npm's registry runs on CouchDB
const npmChangesURL = "https://replicate.npmjs.com/_changes?descending=true&limit=100&include_docs=false" //this changes feed endpoint returns the 100 most recently modified packages in descending order
//the replication mirror replicate.npmjs.com over registry.npmjs.com because it exposes the raw CouchDB changes feed directly
//i personally only want the package names back and not the full metadata, change to include_docs=true if you do... keep in mind that this will make the response bigger

type npmCrawler struct{} //empty struct to purely satisfy the Crawler interface by having FetchNew defined on it

type npmChange struct { //this only maps the id field 
	ID string `json:"id"`
}
type npmChangesResponse struct {
	Results []npmChange `json:"results"`
}

func (n npmCrawler) FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, npmChangesURL, nil) //ties the request to the context.. if the context cancelss, the request aborts (fyi never use http.Get in prod code)
	if err != nil {
		return nil, fmt.Errorf("npm: build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm: fetch changes: %w", err)
	}
	defer resp.Body.Close() //HTTP response bodies are streams backed by open TCP connections... if they aren't closed, you'll leak connections

	var result npmChangesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("npm: decode response: %w", err)
	}
	pkgs := make([]model.Package, 0, len(result.Results)) //pre-allocates slice capacity to avoid repeated heap allocations as there are appends
	for _, change := range result.Results {
		pkgs = append(pkgs, model.Package{
			Ecosystem: model.EcosystemNPM,
			Name:      change.ID,
		})
	}

	return pkgs, nil
}

func init() {
	Register("npm", npmCrawler{}) //runs automatically when the package is imported... registers the npm crawler into the registry map
}