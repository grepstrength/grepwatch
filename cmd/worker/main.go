package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/grepstrength/grepwatch/alert"
	"github.com/grepstrength/grepwatch/crawler"
	"github.com/grepstrength/grepwatch/diff"
	"github.com/grepstrength/grepwatch/model"
	"github.com/grepstrength/grepwatch/store"
)
const (
	pollInterval = 30 * time.Minute //how often the worker wakes up to crawl all registries... 30 minutes is frequent enough to catch new malicious releases quickly, but infrequent enough to stay within rate limits
	lookback = 24 * time.Hour //how far back each crawl looks on the first run. done so the page is not empty on the first deloy
	maxConcurrentDiffs = 4 //bounds how many packages analyzed at once
)

func main() {
	log.Println("grepWatch worker starting") //this with timestamps is enough fora background worker. Raliway captures stdout/stderr autmoatically. this is how logs are generated
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	rootCtx, cancel := context.WithCancel(context.Background()) //parent conext for the entire worker
	defer cancel()
	go handleShutdown(cancel)
	db, err := store.New(rootCtx, connString)
	if err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}
	defer db.Close()
	bc := alert.NewBroadcaster()
	runPollCycle(rootCtx, db, bc)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop() 

	for {
		select {
		case <-ticker.C:
			runPollCycle(rootCtx, db, bc) //time for the next scheduled poll
		case <-rootCtx.Done():
			log.Println("worker shutting down")
			return
		}
	}
}
//this runs one complete crawl-and-analysze pass across every registered crawler. called once on startup and every ticker tick
//each cycle is inpendent
func runPollCycle(ctx context.Context, db *store.Store, bc *alert.Broadcaster) {
	log.Println("poll cycle starting")
	since := time.Now().Add(-lookback) //computer the lookbook window for this cycle 
	sem := make(chan struct{}, maxConcurrentDiffs)
	var wg sync.WaitGroup
	for name, c := range crawler.Registry { //iterate on every registered crawler (npm, pypi, go, cargo, maven, nuget)
		pkgs, err := c.FetchNew(ctx, since)
		if err != nil {
			log.Printf("crawler %s failed: %v", name, err)
			continue
		}

		log.Printf("crawler %s returned %d packages", name, len(pkgs))
		for _, pkg := range pkgs {
			sem <- struct{}{}
			wg.Add(1)
			go func(p model.Package) { //launches he diff in its own goroutine

				defer wg.Done()
				defer func() { <-sem }() 
				analyzeOne(ctx, db, bc, p)
			}(pkg)
		}
	}

	wg.Wait()

	log.Println("poll cycle complete")
}

//this handles the full lifecycle for a  prior to this one to diff againstsingle package
func analyzeOne(ctx context.Context, db *store.Store, bc *alert.Broadcaster, pkg model.Package) {
	prevVersion := "" //need a version immediately
	finding, err := diff.Analyze(ctx, pkg, prevVersion) //run he diff, analyze fetehes both versions, extractions source, and runs every grep function
	if err != nil {
		log.Printf("analyze %s/%s failed: %v", pkg.Ecosystem, pkg.Name, err)
		return
	}
	if len(finding.Signals) == 0 {
		return
	}
	finding.Severity = alert.Score(finding) //score the finding
	if _, err := db.Save(ctx, finding); err != nil { //ensure the finding persists
		log.Printf("save finding for %s/%s failed: %v", pkg.Ecosystem, pkg.Name, err)
		return
	}
	bc.Publish(finding) //broadcasts to any live-feed clients

	log.Printf("FINDING: %s/%s severity=%d signals=%d",
		pkg.Ecosystem, pkg.Name, finding.Severity, len(finding.Signals))
}

func handleShutdown(cancel context.CancelFunc) {

	sigCh := make(chan os.Signal, 1) //make a channel to receive OS signas on
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM) //registers interest in CTRL+C and SIGTERM 

	sig := <-sigCh
	log.Printf("received signal %v, shutting down", sig)
	cancel()
}













