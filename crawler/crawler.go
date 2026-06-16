package crawler

import (
	"context"
	"time"

	"github.com/grepstrength/grepwatch/model"
)

type Crawler interface {
	FetchNew(ctx context.Context, since time.Time) ([]model.Package, error) //this is the contract that every ecosystem crawler must satisfy... one method, one job
}

var Registry =  map[string]Crawler{} //this is a package-level variable

func Register(name string, c Crawler) {
	Registry[name] = c
}