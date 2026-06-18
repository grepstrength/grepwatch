package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/grepstrength/grepwatch/model"
)

const mavenSearchURL = "https://search.maven.org/solrsearch/select" //Maven Central's search API

const mavenRepoBase = "https://repo1.maven.org/maven2" //this is where the artifact files live

const mavenListPath = "data/maven.json"

type mavenWatcher struct {
	packages []string
}
type mavenResponse struct {
	Response mavenResponseBody `json:"response"`
}

type mavenResponseBody struct {
	Docs []mavenDoc `json:"docs"`
}
type mavenDoc struct {
	Version string `json:"v"`
}

func (m *mavenWatcher) Ecosystem() model.Ecosystem {
	return model.EcosystemMaven
}
func (m *mavenWatcher) Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) {
	var results []model.ResolvedPackage

	for _, coord := range m.packages {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		resolved, err := m.checkOne(ctx, store, coord)
		if err != nil {
			continue
		}
		if resolved != nil {
			results = append(results, *resolved)
		}
	}

	return results, nil
}
func (m *mavenWatcher) checkOne(ctx context.Context, store VersionStore, coord string) (*model.ResolvedPackage, error) {
	parts := strings.SplitN(coord, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("maven watch: bad coordinate %q", coord) //malformed allowlist entries are skipped 

	}
	groupID := parts[0]
	artifactID := parts[1]


	//this builds the Solr query, the q parameter filters to exxactly this group and artifact
	//core=gav asks for group/artifact/version granularity
		query := fmt.Sprintf(`g:"%s" AND a:"%s"`, groupID, artifactID)
	url := fmt.Sprintf(
		"%s?q=%s&core=gav&rows=1&sort=timestamp+desc&wt=json",
		mavenSearchURL,
		urlQueryEscape(query),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("maven watch: build request for %s: %w", coord, err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)") //swap out with your own site and user agent if you self-host

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maven watch: fetch %s: %w", coord, err)
	}
	defer resp.Body.Close()

	var meta mavenResponse
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("maven watch: decode %s: %w", coord, err)
	}
	//no docs means the artifact was not found, like for a typo in the list or it was removed from Central
	if len(meta.Response.Docs) == 0 {
		return nil, nil
	}
	latest := meta.Response.Docs[0].Version
	if latest == "" {
		return nil, nil
	}
	//the store is keyed by the full groupId:artifactId and not just artifactId because artifactIds are not globally unique across groups
	lastSeen, err := store.GetLastVersion(ctx, model.EcosystemMaven, coord)
	if err != nil {
		return nil, fmt.Errorf("maven watch: get last version for %s: %w", coord, err)
	}

	if latest == lastSeen {
		return nil, nil
	}

	if err := store.SetLastVersion(ctx, model.EcosystemMaven, coord, latest); err != nil {
		return nil, fmt.Errorf("maven watch: set last version for %s: %w", coord, err)
	}

	if lastSeen == "" {
		return nil, nil
	}

	resolved := &model.ResolvedPackage{ //build the resolved package
		Package: model.Package{
			Ecosystem: model.EcosystemMaven,
			Name:      coord,
			Version:   latest,
		},
		SourceURL:     mavenJarURL(groupID, artifactID, latest),
		PrevVersion:   lastSeen,
		PrevSourceURL: mavenJarURL(groupID, artifactID, lastSeen),
	}
	return resolved, nil
}
 //mavenJarURL constructs the download URL for an artifacts main JAR file
func mavenJarURL(groupID, artifactID, version string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/") //Maven's repo layout is strict and predictable. the groupId's dots become path separators
	return fmt.Sprintf(
		"%s/%s/%s/%s/%s-%s.jar",
		mavenRepoBase,
		groupPath,
		artifactID,
		version,
		artifactID,
		version,
	)
}

//allows special characters survive transport in the URL
func urlQueryEscape(s string) string {
	replacer := strings.NewReplacer(
		" ", "+",
		`"`, "%22",
		":", "%3A",
	)
	return replacer.Replace(s)
}

func init() {
	names, err := loadList(mavenListPath)
	if err != nil {
		names = nil
	}
	Register(&mavenWatcher{packages: names})
}