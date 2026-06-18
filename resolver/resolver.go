package resolver

import (
	"context"

	"github.com/grepstrength/grepwatch/model"
)

type Resolver interface {
	Resolve(ctx context.Context, pkg model.Package) (*model.ResolvedPackage, error) //returns a pointer than a value because resolution can legit produce "nothing to resolve"
}

var Registry = map[model.Ecosystem]Resolver{} //registry is keyed by model.Ecosystem rathern a plain string. the worker takes a package, reads its ecosystem field, and needs to find the matching resolver

func Register(ecosystem model.Ecosystem, r Resolver) {
	Registry[ecosystem] = r
}