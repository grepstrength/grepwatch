package crawler

import (
	"context"
	"encoding/xml" //PyPI's newest-releases feed is RSS which is xML
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grepstrength/grepwatch/model"
)

const pypiFeedURL = "https://pypi.org/rss/updates.xml" //PyPI publishes an RSS feed of recently updated packages. each item is a single release. there's no API key or auth

//the response structs 
type pypiRSS struct {
	Channel struct {
		Items []pypiItem `xml:"item"`
	} `xml:"channel"` //mirrors RSS's nexting
}
type pypiItem struct {
	Title	string `xml:"title"` //the Titlke field in PyPI's feed looks like 'requests x.xx.x'
	Link	string `xml:"link"`
}



type pypiCrawler struct{}
//this is essentially the same as npm... build request with context, fetch, defer-close the body, then decode
func (p pypiCrawler) FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pypiFeedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("pypi: build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi: fetch feed: %w", err)
	}
	defer resp.Body.Close()

	var feed pypiRSS
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("pypi: decode feed: %w", err)
	}

	pkgs := make([]model.Package, 0, len(feed.Channel.Items))
	for _, item := range feed.Channel.Items {
		name, version := parsePypiTitle(item.Title)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Ecosystem: model.EcosystemPyPI,
			Name:      name,
			Version:   version,
			SourceURL: item.Link,
		})
	}

	return pkgs, nil
}
//had to fight the urge to call this 'grepPypiTitle'
func parsePypiTitle(title string) (name, version string) { 
	parts := strings.Fields(title) //splits on any whitespace and discards empty strings... this returns name and version separately
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func init() {
	Register("pypi", pypiCrawler{})
}