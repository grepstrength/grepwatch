package resolver
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/grepstrength/grepwatch/model"
)

const npmRegistryURL = "https://registry.npmjs.org"

type npmResolver struct{}

type npmMetadata struct {
	Versions map[string]npmVersionMeta `json:"versions"`
}

type npmVersionMeta struct {
	Dist npmDist `json:"dist"`
}

type npmDist struct {
	Tarball string `json:"tarball"`
}

func (n npmResolver) Resolve(ctx context.Context, pkg model.Package) (*model.ResolvedPackage, error) {
	url := fmt.Sprintf("%s/%s", npmRegistryURL, pkg.Name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("npm resolve: build request: %w", err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)") //currently set to my own site. just change this to yours in your own fork

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm resolve: fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	var meta npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("npm resolve: decode metadata: %w", err)
	}

	prevVersion := findPreviousVersion(meta.Versions, pkg.Version)
	if prevVersion == "" {
		return nil, nil
	}

	resolved := &model.ResolvedPackage{
		Package:       pkg,
		SourceURL:     meta.Versions[pkg.Version].Dist.Tarball,
		PrevVersion:   prevVersion,
		PrevSourceURL: meta.Versions[prevVersion].Dist.Tarball,
	}
	return resolved, nil
}
//collects all version strings, sorts them and walks until it hits the current version
func findPreviousVersion(versions map[string]npmVersionMeta, current string) string {
	all := make([]string, 0, len(versions))
	for v := range versions {
		all = append(all, v)
	}
	sort.Strings(all) //uses lexical stringsorting for now, but its not true semantic-version sorting... v1.10.0 goes before 1.9.0 because 1 < 9 
	//proper semantic sorting requires a semver parsing library... maybe later

	prev := ""
	for _, v := range all {
		if v == current {
			break
		}
		prev = v
	}
	return prev
}

func init() {
	Register(model.EcosystemNPM, npmResolver{})
}