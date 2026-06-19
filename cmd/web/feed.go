package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/grepstrength/grepwatch/model"
)

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
//the handler
func (s *server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, err := s.db.Recent(r.Context(), 50) //the same source the JSON and SSE endpoints
	if err != nil {
		log.Printf("handleFeed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	feed := buildFeed(findings, "https://grepwatch.com") //this is my own site, just replace with yours if you decide to self host

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	if _, err := w.Write([]byte(xml.Header)); err != nil { //
		return //client went away mid-write so nothing useful to do
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ") //make it human-readable
	if err := enc.Encode(feed); err != nil {
		log.Printf("handleFeed encode: %v", err)
	}
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