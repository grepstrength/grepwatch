package alert

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/grepstrength/grepwatch/model"
)

//Broadcaster fans out 
type Broadcaster struct {
	mu sync.Mutex //mu guards the clients map. every rw has to hold this lock because Publish and (un)Subscribe run concurrently. would panic otherwise
	clients map[chan string]bool //each connector gets its own channel
}
/*
this computes a final severity score for a finding by summing the weights of all its signals and mapping that sum onto the Severityscale
the weights are summed because packages that add a new outbound URL AND have a string with high entropy AND adds an install hook are more suspicious than any single one of these
*/
func Score(f *model.Finding) model.Severity {
	total := 0 //total accumulates the weight of every signal... starts at zero
	for _, sig := range f.Signals {
		total += sig.Weight
	}
	switch { //map the raw weight sum onto the Severity scale. this is intentionally tuned so a single low weight signal stays low, but multiples compound quickly
	case total == 0:
		return model.SeverityNone //nothing suspicious
	case total <= 2:
		return model.SeverityLow //one minor signal 
	case total <= 4:
		return model.SeverityMedium //one moderate signal or small ones compounding
	case total <= 6:
		return model.SeverityHigh //multiple signals combined or a high weight (raw IP)
	default:
		return model.SeverityCritical //total >= 7... if its this bad, it should hopefully be a true supply chain compromise and not an FP
	}
}

//constructs a read to use Broadcaster with its clients map initialized. use this rather than &Broadcaster{} 
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		clients: make(map[chan string]bool),
	}
}

//Subscribe registers a new client and returns a channel that will receive every finding pbulished 
func (b *Broadcaster) Subscribe() chan string {
	ch := make(chan string, 10)

	b.mu.Lock()
	defer b.mu.Unlock()
	b.clients[ch] = true

	return ch
}
//Unsubscribe removes a client and closes its channel. the webserver calls this when the browser's connection drops so it stops trying to send to a client that's no longer there
func (b *Broadcaster) Unsubscribe(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.clients[ch] {
		delete(b.clients, ch)
		close(ch)
	}
}
//Publish seriealises a finding to JSON and sends it to every connected client
func (b *Broadcaster) Publish(f *model.Finding) {
	payload, err := json.Marshal(f)
	if err != nil {
		fmt.Printf("alert: failed to marshal finding: %v\n", err)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- string(payload):
		default:
		}
	}
}
func FormatSSE(payload string) string {
	return fmt.Sprintf("data: %s\n\n", payload)
}