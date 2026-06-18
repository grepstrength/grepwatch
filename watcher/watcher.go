package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/grepstrength/grepwatch/model"
)

/*
*** Super Duper Important *** 

Watcher is the contact that every ecosystem watcher implements
This is self-driving. It owns an allowlist of packages to monitor, and when asked to check, fetches each packages current metadata
Returns ones whose latest version is newer than what was last recorded
*/

type Watcher interface {
	Check(ctx context.Context, store VersionStore) ([]model.ResolvedPackage, error) //polls every package in the watcher's allowlist
	Ecosystem() model.Ecosystem //reports which ecosystem this watcher handels
}
//VersionStore is the narrow slice of sotrage behavior a watcher needs > read the last-seen > record a new one
type VersionStore interface {
	GetLastVersion(ctx context.Context, ecosystem model.Ecosystem, name string) (string, error)
	SetLastVersion(ctx context.Context, ecosystem model.Ecosystem, name, version string) error
}

//holds all active watchers keyed by the ecosystem
var Registry = map[model.Ecosystem]Watcher{}
//adds a watcher to the registry
func Register(w Watcher) {
	Registry[w.Ecosystem()] = w
}
//loadList reads a JSON array of package names from disk
func loadList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load list %s: %w", path, err)
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, fmt.Errorf("parse list %s: %w", path, err)
	}
	return names, nil
}