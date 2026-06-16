package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/grepstrength/grepwatch/model"
)

const cargoRecentURL = "https://crates.io/api/v1/summary" //crates.io's summary endpoint returns several lists in one response, including just_updated


//the summary endpoint returns multiple irrelevant arrays for what's needed for this
type cargoSummary struct {
	JustUpdated []cargoCrate `json:"just_updated"`
}

type cargoCrate struct {
	Name       string `json:"name"`
	MaxVersion string `json:"max_version"`
}

type cargoCrawler struct{}
func (c cargoCrawler) FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cargoRecentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cargo: build request: %w", err)
	}

	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)") //cates.io rejects requests without a descriptive User-Agent... replace for whatever you want if you fork

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cargo: fetch summary: %w", err)
	}
	defer resp.Body.Close()

	var summary cargoSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return nil, fmt.Errorf("cargo: decode summary: %w", err)
	}

	pkgs := make([]model.Package, 0, len(summary.JustUpdated))
	for _, crate := range summary.JustUpdated {
		pkgs = append(pkgs, model.Package{
			Ecosystem: model.EcosystemCargo,
			Name:      crate.Name,
			Version:   crate.MaxVersion,
		})
	}

	return pkgs, nil
}

func init() {
	Register("cargo", cargoCrawler{})
}