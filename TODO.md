# grepWatch — Roadmap

## Shipped — v1.1 watcher layer
Self-driving watchers replaced the crawl→resolve split. Each reads a checked-in
allowlist, fetches metadata once, tracks last-seen version in Postgres
(watched_versions), and emits a fully-resolved package to the diff engine on a
real version change.
- [x] watched_versions store + Get/SetLastVersion
- [x] Watcher interface + all six watchers (npm, PyPI, Cargo, Maven, NuGet, Go)
- [x] Worker drives watchers; diff.Analyze takes model.ResolvedPackage
- [x] Real top-1000 allowlists per ecosystem (cmd/genlists, via ecosyste.ms)
- [x] Removed obsolete crawler/, resolver/, cmd/watchertest
- [x] Diff-engine regression tests (severity tiers, new-not-old, entropy threshold)
- [x] RSS 2.0 feed of findings (/feed.xml)
- [x] Frontend liveness UI: scrolling "watching" ticker (static representative
      list, cosmetic), connection-state "Live" pill, scope-framed empty state

## Known limitations 
- **Go threat mismatch**: Go's dominant vector is typosquatting, not malicious
  updates to popular modules — the allowlist+diff model misses the former.
- **Maven scans bytecode, not source**: fetches the compiled .jar; prefer
  -sources.jar when published.
- **grepImports is substring, not AST**: per-ecosystem AST parsing would cut
  false positives. (Saw this firsthand — "net" matching inside ordinary words.)
- (Semver/latest-version trust is an intentional design choice, not a bug.)

## Hardening before "production-ready"
- [ ] Remove localhost dev origins from the CORS allowlist (cmd/web/main.go),
      leaving only the grepwatch.com origins.
- [ ] Cross-process SSE bridge (Postgres LISTEN/NOTIFY) so worker findings reach
      web-process browsers live in the two-service deploy.
- (Last-poll timestamp is now effectively handled by watched_versions.)

## Next — dynamic feed
The watchers produce real scan activity, so what was blocked on "truthful
resolvers" is now buildable:
- [ ] Stats counter (cumulative packages scanned, findings to date) — real
      backend tally + /api/stats; the cosmetic ticker is NOT this
- [ ] Benign-activity ticker (sampled clean scans, tagged SSE envelope)
- [ ] Go-specific typosquat detection (separate from the allowlist+diff model)