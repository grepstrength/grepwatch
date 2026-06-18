package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/grepstrength/grepwatch/model"
)
//NuGet's flat container API. FYI the "index.json" for a package lists every published version. 
//NuGet lowercases package IDs

const nugetFlatBase = "https://api.nuget.org/v3-flatcontainer"
const nugetListPath = "data/nuget.json"

type nugetWatcher struct {
	packages []string
}

//this is the shape of a packages index.json
type nugetIndex struct {
	Versions []string `json:"versions"`
}

func (n *nugetWatcher) Ecosystem() model.Ecosystem {
	return model.EcosystemNuGet
}

func (n *nugetWatcher) Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) {
	var results []model.ResolvedPackage
	for _, name := range n.packages {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		resolved, err := n.checkOne(ctx, store, name)
		if err != nil {
			continue
		}
		if resolved != nil {
			results = append(results, *resolved)
		}
	}
	return results, nil
}


func (n *nugetWatcher) checkOne(ctx context.Context, store VersionStore, name string) (*model.ResolvedPackage, error) {
	idLower := strings.ToLower(name) //NuGet's URLs require the package ID in loewrcase
	url := fmt.Sprintf("%s/%s/index.json", nugetFlatBase, idLower)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil { //I honestly love Go's explicit error handling 
		return nil, fmt.Errorf("nuget watch: build request for %s: %w", name, err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)") //swap out the site and user agent with yours if you self-host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nuget watch: fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	var index nugetIndex
	if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
		return nil, fmt.Errorf("nuget watch: decode %s: %w", name, err)
	}

	if len(index.Versions) == 0 { //the versions array is ordered oldest to newest, so the latest is the last. since NuGet maintains he ordering, trust it rather tan trying to sort it yourself. if you do, then you hit the lexical semver problem
		return nil, nil
	}
	latest := index.Versions[len(index.Versions)-1]

	lastSeen, err := store.GetLastVersion(ctx, model.EcosystemNuGet, name)
	if err != nil {
		return nil, fmt.Errorf("nuget watch: get last version for %s: %w", name, err)
	}

	if latest == lastSeen {
		return nil, nil
	}

	if err := store.SetLastVersion(ctx, model.EcosystemNuGet, name, latest); err != nil {
		return nil, fmt.Errorf("nuget watch: set last version for %s: %w", name, err)
	}

	if lastSeen == "" {
		return nil, nil
	}

	resolved := &model.ResolvedPackage{
		Package: model.Package{
			Ecosystem: model.EcosystemNuGet,
			Name:      name,
			Version:   latest,
		},
		SourceURL:     nugetPackageURL(idLower, latest),
		PrevVersion:   lastSeen,
		PrevSourceURL: nugetPackageURL(idLower, lastSeen),
	}
	return resolved, nil
}
//this builds the domainload URL for  a.nupkg file
func nugetPackageURL(idLower, version string) string {
	versionLower := strings.ToLower(version)
	return fmt.Sprintf(
		"%s/%s/%s/%s.%s.nupkg", //NuGet has a deterministic layout, all lower case, and the .nupkg is a zip archive, which the diff engine will extract with its zip path
		nugetFlatBase,
		idLower,
		versionLower,
		idLower,
		versionLower,
	)
}

func init() {
	names, err := loadList(nugetListPath)
	if err != nil {
		names = nil
	}
	Register(&nugetWatcher{packages: names})
}