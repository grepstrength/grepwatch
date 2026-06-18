package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grepstrength/grepwatch/model"
)

const pypiJSONURL = "https://pypi.org/pypi"
const pypiListPath = "data/pypi.json"

type pypiWatcher struct {
	packages []string
}//this maps the pats of PyPI's JSON needed
type pypiMetadata struct {
	Info     pypiInfo                 `json:"info"`
	Releases map[string][]pypiFile    `json:"releases"`
}

type pypiInfo struct {
	Version string `json:"version"`
}

type pypiFile struct {
	URL         string `json:"url"`
	PackageType string `json:"packagetype"`
}

func (p *pypiWatcher) Ecosystem() model.Ecosystem {
	return model.EcosystemPyPI
}

func (p *pypiWatcher) Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) {
	var results []model.ResolvedPackage

	for _, name := range p.packages {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		resolved, err := p.checkOne(ctx, store, name)
		if err != nil {
			continue
		}
		if resolved != nil {
			results = append(results, *resolved)
		}
	}

	return results, nil
}

func (p *pypiWatcher) checkOne(ctx context.Context, store VersionStore, name string) (*model.ResolvedPackage, error) {
	url := fmt.Sprintf("%s/%s/json", pypiJSONURL, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("pypi watch: build request for %s: %w", name, err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi watch: fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	var meta pypiMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("pypi watch: decode %s: %w", name, err)
	}

	latest := meta.Info.Version
	if latest == "" {
		return nil, nil
	}

	lastSeen, err := store.GetLastVersion(ctx, model.EcosystemPyPI, name)
	if err != nil {
		return nil, fmt.Errorf("pypi watch: get last version for %s: %w", name, err)
	}

	if latest == lastSeen {
		return nil, nil
	}

	if err := store.SetLastVersion(ctx, model.EcosystemPyPI, name, latest); err != nil {
		return nil, fmt.Errorf("pypi watch: set last version for %s: %w", name, err)
	}

	if lastSeen == "" {
		return nil, nil
	}

	resolved := &model.ResolvedPackage{
		Package: model.Package{
			Ecosystem: model.EcosystemPyPI,
			Name:      name,
			Version:   latest,
		},
		SourceURL:     pickSdist(meta.Releases[latest]),
		PrevVersion:   lastSeen,
		PrevSourceURL: pickSdist(meta.Releases[lastSeen]),
	}
	return resolved, nil
}
//returns the source-distribution URL from a release's file list. you want the sdist rather than a prebuilt whell becuase thats what the diff engine scans
func pickSdist(files []pypiFile) string {
	for _, f := range files {
		if f.PackageType == "sdist" {
			return f.URL
		}
	}
	if len(files) > 0 {
		return files[0].URL
	}
	return ""
}

func init() {
	names, err := loadList(pypiListPath)
	if err != nil {
		names = nil
	}
	Register(&pypiWatcher{packages: names})
}
