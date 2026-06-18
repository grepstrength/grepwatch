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
	"github.com/grepstrength/grepwatch/watcher" //replaced crawler
	"github.com/grepstrength/grepwatch/diff"
	"github.com/grepstrength/grepwatch/model"
	"github.com/grepstrength/grepwatch/store"
)
const ( //no longer need the lookback const in this version
	pollInterval = 30 * time.Minute //how often the worker wakes up to crawl all registries... 30 minutes is frequent enough to catch new malicious releases quickly, but infrequent enough to stay within rate limits
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

	sem := make(chan struct{}, maxConcurrentDiffs) //each diff downloads two archives and cap how many run at once
	var wg sync.WaitGroup
	for eco, w := range watcher.Registry { //iterate on every registered watcher (npm, pypi, go, cargo, maven, nuget)
		resolved, err := w.Check(ctx, db)
		if err != nil {
			log.Printf("watcher %s failed: %v", eco, err)
			continue //if one ecosystem fails, it shouldn't kill the whole cycle
		}

		log.Printf("watcher %s returned %d changed packages", eco, len(resolved))
		for _, rp := range resolved {
			sem <- struct{}{} //blocks once maxCncurrentDiffs are in flight
			wg.Add(1)
			go func(p model.ResolvedPackage) { //pass rp in as a param

				defer wg.Done()
				defer func() { <-sem }() //releases the slot when this diff finishes
				analyzeOne(ctx, db, bc, p)
			}(rp)
		}
	}

	wg.Wait() //dont return until every diff launched this cycle has finished

	log.Println("poll cycle complete")
}

//this handles the full lifecycle for a  prior to this one to diff againstsingle package
func analyzeOne(ctx context.Context, db *store.Store, bc *alert.Broadcaster, rp model.ResolvedPackage) {
	finding, err := diff.Analyze(ctx, rp) //rp carries the real previous version and both URLs
	if err != nil {
		log.Printf("analyze %s/%s failed: %v", rp.Package.Ecosystem, rp.Package.Name, err)
		return
	}
	if len(finding.Signals) == 0 {
		return //diffed cleanly = nothing suspicious
	}
	finding.Severity = alert.Score(finding) //score the finding
	if _, err := db.Save(ctx, finding); err != nil {
		log.Printf("save finding for %s/%s failed: %v", rp.Package.Ecosystem, rp.Package.Name, err)
		return
	}
	bc.Publish(finding) //broadcasts to any live-feed clients

	log.Printf("FINDING: %s/%s severity=%d signals=%d",
		rp.Package.Ecosystem, rp.Package.Name, finding.Severity, len(finding.Signals))
}

func handleShutdown(cancel context.CancelFunc) {

	sigCh := make(chan os.Signal, 1) //make a channel to receive OS signas on
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM) //registers interest in CTRL+C and SIGTERM 

	sig := <-sigCh
	log.Printf("received signal %v, shutting down", sig)
	cancel()
}













