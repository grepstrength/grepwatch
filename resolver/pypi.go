package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/grepstrength/grepwatch/model"
)

//PyPi exposes a clean JSON metadata endpoint at /pypi/<PACKAGE>/json
const pypiJSONURL = "https://pypi.org/pypi"
type pypiResolver struct{} //empty struct that satisfies the Resolver interface
type pypiMetadata struct {
	Releases map[string][]pypiFile `json:"releases"` //keyed by version string, with each version mapping to a list of files and not a single download
}
//one downloadable artifact within a release. we only need the URL and its type
type pypiFile struct {
	URL string 	`json:"url"`
	PackageType string `json:"packagetype"` 
}

//this fetches PyPI metadata for the package > finds the version that preceded the given one > returns both versions source-tarball URLs
func (p pypiResolver) Resolve(ctx context.Context, pkg model.Package) (*model.ResolvedPackage, error) {
	url := fmt.Sprintf("%s/%s/json", pypiJSONURL, pkg.Name) //builds the metadata URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //ties the request to the caller's context so it cacnels cleanly on wrker shutdown or timeout
	if err != nil {
		return nil, fmt.Errorf("pypi resolve: build request: %w", err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi resolve: fetch metadata: %w", err)
	}
	defer resp.Body.Close() //always close the body to avoid leaking the connection

	var meta pypiMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("pypi resolve: decode metadata: %w", err)
	}
	versions := make([]string, 0, len(meta.Releases)) //collects every version string into a slice so it can be sorted
	for v := range meta.Releases {
		versions = append(versions, v)
	}

	sort.Strings(versions) //lexical sort, and not a true semver. works for most instances, but it WILL misorder things like "v1.10.0" vs "1.9.0"... this is tracked in TODO as a shared fix among all the resolvers

	//walk the sorted versions... the one immediately before the current version is its predecessor. this is whats diffed against
	prevVersion := ""
	for _, v := range versions {
		if v == pkg.Version {
			break
		}
		prevVersion = v
	}

	if prevVersion == "" { //no predecessor means thi is the first release, meaning there is nothingto diff
		return nil, nil
	}
	//build the resolved package, picking the sdist URL for each version
	resolved := &model.ResolvedPackage{
		Package:       pkg,
		SourceURL:     pickSdist(meta.Releases[pkg.Version]),
		PrevVersion:   prevVersion,
		PrevSourceURL: pickSdist(meta.Releases[prevVersion]),
	}
	return resolved, nil
}

//pickSdist returns the URL of the source distribution from a releases file list.
//specifically want the sdist because it contaisn actual sourcecode to scan
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

//init registers this resolver under the PyPI ecosystem when the package loads, so the worker can look it up by ecosystem
func init() {
	Register(model.EcosystemPyPI, pypiResolver{})
}