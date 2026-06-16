package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/grepstrength/grepwatch/alert"
	"github.com/grepstrength/grepwatch/store"
)

//replace these variables with whatever you want for your own fork
var allowedOrigins = map[string]bool{
	"https://grepwatch.com":     true,
	"https://www.grepwatch.com": true,
	"http://localhost:5173":     true,
	"http://localhost:3000":     true,
}

type server struct {
	db *store.Store
	bc *alert.Broadcaster
}


func main() {
	log.Println("grepWatch web server starting")
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	ctx := context.Background()

	db, err := store.New(ctx, connString) //connect to Postgres
	if err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}
	defer db.Close()

	bc := alert.NewBroadcaster() //the broadcaster browsers will connect to 

	srv := &server{db: db, bc: bc} //bulid the server with its dependencies

	mux := http.NewServeMux() //NewServerMux is the standard requst router
	mux.HandleFunc("/api/findings", srv.handleFindings) //REST endpoint, returns recent findings as JSON for the page's initial load
	mux.HandleFunc("/api/findings/live", srv.handleLive) //SSE endpoint, a long-lived connection that streams new findings live
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { //healthcheck so Railway and uptime monitors can confirm the service is alive
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	addr := ":" + port
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, withCORS(mux)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	findings, err := s.db.Recent(ctx, 50)
	if err != nil {
		log.Printf("handleFindings: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError) //returns a generic message to the client while the real error goes to log.Printf server-side
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(findings); err != nil {
		log.Printf("handleFindings encode: %v", err)
	}
}

func (s *server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientCh := s.bc.Subscribe()
	defer s.bc.Unsubscribe(clientCh)
	keepAlive := time.NewTicker(30 * time.Second)
	defer keepAlive.Stop()
	ctx := r.Context()

	for { //streaming loop
		select {
		case msg, open := <-clientCh:
			if !open {
				return
			}
			_, _ = w.Write([]byte(alert.FormatSSE(msg)))
			flusher.Flush()

		case <-keepAlive.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()

		case <-ctx.Done():
			return
		}
	}
}

//the withCORS wraps a handler to Cross-Origin Resource Sharing headers
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")

		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}