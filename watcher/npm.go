package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grepstrength/grepwatch/model"
)

//this is npm's package metadata endpoint base
const npmRegistryURL = "https://registry.npmjs.org"

const npmListPath = "data/npm.json" //where the watcher's allowlist of package names lives

type npmWatcher struct {
	packages []string
}


type npmMetadata struct {
	DistTags npmDistTags               `json:"dist-tags"`
	Versions map[string]npmVersionMeta `json:"versions"`
}

type npmDistTags struct {
	Latest string `json:"latest"`
}

type npmVersionMeta struct {
	Dist npmDist `json:"dist"`
}

type npmDist struct {
	Tarball string `json:"tarball"`
}

func (n *npmWatcher) Ecosystem() model.Ecosystem {
	return model.EcosystemNPM
}

//check walks the allowlist, fetches each packages metadata, and returns the ones whose latest version is newer than the last recorded on
func (n *npmWatcher) Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) {
	var results []model.ResolvedPackage

	for _, name := range n.packages {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		resolved, err := n.checkOne(ctx, store, name)
		if err != nil {
			continue //if one package fails, it cant stop the whole cycle 
		}
		if resolved != nil {
			results = append(results, *resolved)
		}
	}
	return results, nil
}

//this handles a single package: fetch metadata, compare the latest version against what was last seen
func (n *npmWatcher) checkOne(ctx context.Context, store VersionStore, name string) (*model.ResolvedPackage, error) {
	url := fmt.Sprintf("%s/%s", npmRegistryURL, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("npm watch: build request for %s: %w", name, err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm watch: fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	var meta npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("npm watch: decode %s: %w", name, err)
	}

	latest := meta.DistTags.Latest
	if latest == "" { //no "latest" tag means nothing usable to check
		return nil, nil
	}

	lastSeen, err := store.GetLastVersion(ctx, model.EcosystemNPM, name)
	if err != nil {
		return nil, fmt.Errorf("npm watch: get last version for %w", name, err)
	}
	if latest == lastSeen {
		return nil, nil
	}
	if err := store.SetLastVersion(ctx, model.EcosystemNPM, name, latest); err != nil { //the version changed and/or this is the first time its been seen
		return nil, fmt.Errorf("npm watch: set last version for %s: %w", name, err)
	}

	if lastSeen == "" {
		return nil, nil
	}
	//genuine version change from lastseen > latest
	newTarball := meta.Versions[latest].Dist.Tarball
	prevTarball := meta.Versions[lastSeen].Dist.Tarball

	resolved := &model.ResolvedPackage{
		Package: model.Package{
			Ecosystem: model.EcosystemNPM,
			Name:      name,
			Version:   latest,
		},
		SourceURL:     newTarball,
		PrevVersion:   lastSeen,
		PrevSourceURL: prevTarball,
	}
	return resolved, nil
}


func init() {
	names, err := loadList(npmListPath)
	if err != nil {
		names = nil
	}
	Register(&npmWatcher{packages: names})
}