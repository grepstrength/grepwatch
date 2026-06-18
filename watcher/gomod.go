package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/mod/module"

	"github.com/grepstrength/grepwatch/model"
)

const goProxyBase = "https://proxy.golang.org" //gomod's proxy. /@latest teslls us the current version while /@v/list returns every known version. this proxy serves plain text
const goListPath = "data/go.json"

type goWatcher struct {
	packages []string
}
//goLatest is the tiny JSON object the /@latest endpoint returns. the only field needed is version
type goLatest struct {
	Version string `json:"Version"`
}

func (g *goWatcher) Ecosystem() model.Ecosystem {
	return model.EcosystemGo
}

func (g *goWatcher) Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) {
	var results []model.ResolvedPackage

	for _, name := range g.packages {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		resolved, err := g.checkOne(ctx, store, name)
		if err != nil {
			continue
		}
		if resolved != nil {
			results = append(results, *resolved)
		}
	}

	return results, nil
}

func (g *goWatcher) checkOne(ctx context.Context, store VersionStore, name string) (*model.ResolvedPackage, error) {
	//go module paths can contain uppercase letters, but the proxy stores them case-encoded
	//need EscapePath to do this correctly, because without it, any module with caps (like BurtSushi) will 404
	escaped, err := module.EscapePath(name)
	if err != nil {
		return nil, fmt.Errorf("go watch: escape path %s: %w", name, err)
	}

	latest, err := g.fetchLatest(ctx, escaped, name)
	if err != nil {
		return nil, err
	}
	if latest == "" {
		return nil, nil
	}

	lastSeen, err := store.GetLastVersion(ctx, model.EcosystemGo, name)
	if err != nil {
		return nil, fmt.Errorf("go watch: get last version for %s: %w", name, err)
	}

	if latest == lastSeen {
		return nil, nil
	}

	if err := store.SetLastVersion(ctx, model.EcosystemGo, name, latest); err != nil {
		return nil, fmt.Errorf("go watch: set last version for %s: %w", name, err)
	}

	if lastSeen == "" {
		return nil, nil
	}

	resolved := &model.ResolvedPackage{
		Package: model.Package{
			Ecosystem: model.EcosystemGo,
			Name:      name,
			Version:   latest,
		},
		SourceURL:     goZipURL(escaped, latest),
		PrevVersion:   lastSeen,
		PrevSourceURL: goZipURL(escaped, lastSeen),
	}
	return resolved, nil
}

//fetchLatest queries the proxy's /@latest endpoint and returns a small JSON object naming the current version
func (g *goWatcher) fetchLatest(ctx context.Context, escapedPath, name string) (string, error) {
	url := fmt.Sprintf("%s/%s/@latest", goProxyBase, escapedPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("go watch: build latest request for %s: %w", name, err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)") //swap with your own site and user agent if you want to self host

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("go watch: fetch latest for %s: %w", name, err)
	}
	defer resp.Body.Close()

	var latest goLatest
	if err := json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		return "", fmt.Errorf("go watch: decode latest for %s: %w", name, err)
	}

	return latest.Version, nil
}
//this is used to build the module zip download URL
//the proxy serves module source as a zip at /@v/<VERSION>.zip
//need to URL-escape the version because Go versions can contain build metadata like "+incompatible" which must be encoded
func goZipURL(escapedPath, version string) string {
	return fmt.Sprintf("%s/%s/@v/%s.zip", goProxyBase, escapedPath, url.PathEscape(version))
}

func init() {
	names, err := loadList(goListPath)
	if err != nil {
		names = nil
	}
	Register(&goWatcher{packages: names})
}