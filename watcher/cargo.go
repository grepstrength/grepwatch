package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grepstrength/grepwatch/model"
)

const cratesAPIURL = "https://crates.io/api/v1/crates"
const cargoListPath = "data/cargo.json"

type cargoWatcher struct {
	packages []string
}

//maps crates.io's response
type cargoMetadata struct {
	Crate    cargoCrate     `json:"crate"`
	Versions []cargoVersion `json:"versions"`
}
type cargoCrate struct {
	NewestVersion string `json:"newest_version"` //the authoritative latest
}
type cargoVersion struct {
	Num    string `json:"num"`
	DlPath string `json:"dl_path"`
}
func (c *cargoWatcher) Ecosystem() model.Ecosystem {
	return model.EcosystemCargo
}
func (c *cargoWatcher) Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) {
	var results []model.ResolvedPackage

	for _, name := range c.packages {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		resolved, err := c.checkOne(ctx, store, name)
		if err != nil {
			continue
		}
		if resolved != nil {
			results = append(results, *resolved)
		}
	}

	return results, nil
}

func (c *cargoWatcher) checkOne(ctx context.Context, store VersionStore, name string) (*model.ResolvedPackage, error) {
	url := fmt.Sprintf("%s/%s", cratesAPIURL, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("cargo watch: build request for %s: %w", name, err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)") //you can swap this out for your own host and user agent if you decide to self host

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cargo watch: fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	var meta cargoMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("cargo watch: decode %s: %w", name, err)
	}

	latest := meta.Crate.NewestVersion
	if latest == "" {
		return nil, nil
	}

	lastSeen, err := store.GetLastVersion(ctx, model.EcosystemCargo, name)
	if err != nil {
		return nil, fmt.Errorf("cargo watch: get last version for %s: %w", name, err)
	}

	if latest == lastSeen {
		return nil, nil
	}

	if err := store.SetLastVersion(ctx, model.EcosystemCargo, name, latest); err != nil {
		return nil, fmt.Errorf("cargo watch: set last version for %s: %w", name, err)
	}

	if lastSeen == "" {
		return nil, nil
	}

	resolved := &model.ResolvedPackage{
		Package: model.Package{
			Ecosystem: model.EcosystemCargo,
			Name:      name,
			Version:   latest,
		},
		SourceURL:     cargoDownloadURL(meta.Versions, latest),
		PrevVersion:   lastSeen,
		PrevSourceURL: cargoDownloadURL(meta.Versions, lastSeen),
	}
	return resolved, nil
}
//this finds the download path for a speciic version in the versions list
func cargoDownloadURL(versions []cargoVersion, version string) string {
	for _, v := range versions {
		if v.Num == version {
			return "https://crates.io" + v.DlPath //this is prefixed to make it absolute
		}
	}
	return ""
}

func init() {
	names, err := loadList(cargoListPath)
	if err != nil {
		names = nil
	}
	Register(&cargoWatcher{packages: names})
}