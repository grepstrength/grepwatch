package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"sync"

	"github.com/grepstrength/grepwatch/model"
)

var (
	feedMu      sync.Mutex
	feedCached  []byte 
	feedBuiltAt time.Time
)

const feedCacheTTL = 60 * time.Second

//RSS 2.0 doc model

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"` //<rss version="2.0">
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title         string    `xml:"title"`
	Link          string    `xml:"link"`
	Description   string    `xml:"description"`
	LastBuildDate string    `xml:"lastBuildDate"`
	Items         []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string  `xml:"title"`
	Link        string  `xml:"link"`
	Description string  `xml:"description"`
	Category    string  `xml:"category,omitempty"`
	PubDate     string  `xml:"pubDate"`
	GUID        rssGUID `xml:"guid"`
}

//this is an attribute and text content, so its its own struct
type rssGUID struct {
	Value       string `xml:",chardata"`
	IsPermaLink bool   `xml:"isPermaLink,attr"`
}
//the handler now serves from cache instead of hitting the DB every request
func (s *server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := s.cachedFeed(r.Context())
	if err != nil {
		log.Printf("handleFeed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300") //readers/CDNs cache 5 min too
	w.Write(body)
}
//quick fix because some ppl immediately figured out how to exploit this lol...  returns the rendered feed, ensuring the cahed copy is older than the feedChaceTTL
func (s *server) cachedFeed(ctx context.Context) ([]byte, error) {
	feedMu.Lock()
	defer feedMu.Unlock()

	if feedCached != nil && time.Since(feedBuiltAt) < feedCacheTTL {
		return feedCached, nil //fresh enough — no DB hit
	}

	findings, err := s.db.Recent(ctx, 50)
	if err != nil {
		return nil, err
	}
	feed := buildFeed(findings, "https://grepwatch.com") //obviously, swap with your own domain
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		return nil, err
	}

	feedCached = buf.Bytes()
	feedBuiltAt = time.Now()
	return feedCached, nil
}
//turns the findings slice into the RSS document. kept separate from the handler so it's pure (no http, no db) and easily testable
func buildFeed(findings []model.Finding, siteURL string) rssFeed {
	items := make([]rssItem, 0, len(findings))
	for _, f := range findings {
		items = append(items, rssItem{
			Title:       feedTitle(f),
			Link:        siteURL, 
			Description: feedDescription(f),
			Category:    string(f.Package.Ecosystem),
			PubDate:     f.AnalyzedAt.Format(time.RFC1123Z),
			GUID:        rssGUID{Value: feedGUID(f), IsPermaLink: false},
		})
	}

	return rssFeed{
		Version: "2.0",
		Channel: rssChannel{
			Title:         "grepWatch — malicious dependency findings", //swap out the title if you self-host
			Link:          siteURL,
			Description:   "Suspicious changes detected in npm, PyPI, Go, Cargo, Maven, and NuGet package updates.",
			LastBuildDate: time.Now().UTC().Format(time.RFC1123Z),
			Items:         items,
		},
	}
}

func feedTitle(f model.Finding) string {
	return fmt.Sprintf("[%s] %s/%s %s (was %s) — %d signal(s)",
		severityLabel(f.Severity),
		f.Package.Ecosystem, f.Package.Name, f.Package.Version,
		f.PrevVersion, len(f.Signals))
}

func feedDescription(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Severity: %s. ", severityLabel(f.Severity))
	for _, sig := range f.Signals {
		fmt.Fprintf(&b, "%s: %s", sig.Kind, sig.Description)
		if len(sig.Evidence) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(sig.Evidence, ", "))
		}
		b.WriteString(". ")
	}
	return strings.TrimSpace(b.String())
}

//this is a stable unique ID per finding
func feedGUID(f model.Finding) string {
	return fmt.Sprintf("tag:grepwatch.com,2026:%s/%s@%s:%d", //obviosuly swap out your own domain if you sel-host
		f.Package.Ecosystem, f.Package.Name, f.Package.Version, f.AnalyzedAt.Unix())
}

func severityLabel(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "CRITICAL"
	case model.SeverityHigh:
		return "HIGH"
	case model.SeverityMedium:
		return "MEDIUM"
	case model.SeverityLow:
		return "LOW"
	default:
		return "NONE"
	}
}