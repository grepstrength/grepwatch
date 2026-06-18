# grepWatch — Roadmap

## In progress: v1.1 watcher layer
Replaced the crawl→resolve split with self-driving "watchers." Each watcher
reads a checked-in allowlist, fetches each package's metadata once, tracks the
last-seen version in Postgres (watched_versions table), and on a real version
change emits a fully-resolved package (new + previous version + both download
URLs) straight to the diff engine. One metadata fetch does discovery AND
resolution.

- [x] Store layer: watched_versions table + GetLastVersion/SetLastVersion
- [x] Watcher interface (watcher/watcher.go) + shared loadList
- [x] npm watcher (registry.npmjs.org metadata, dist-tags.latest) — validated live
- [x] PyPI watcher (pypi.org/pypi/<pkg>/json, info.version, picks sdist)
- [x] Cargo watcher (crates.io API, newest_version, dl_path)
- [x] Maven watcher (Solr search API + constructed repo1 jar URLs)
- [x] NuGet watcher (flat-container index.json, last element = latest)
- [x] Go watcher (proxy.golang.org /@latest, module.EscapePath) — last one
- [ ] Wire worker (cmd/worker) to drive watchers instead of crawlers/resolvers
- [ ] Change diff.Analyze to accept model.ResolvedPackage
- [ ] Generate real top-1000 allowlists per ecosystem (currently 20-pkg seeds)
- [ ] Delete obsolete crawler/ and resolver/ directories + cmd/watchertest
- [ ] End-to-end validation against a known-bad historical package

## Known limitations to fix
- **Semver / latest-version trust**: watchers trust each registry's own
  "latest" field (dist-tags, info.version, newest_version, ordered list)
  rather than sorting, which sidesteps the lexical-vs-semver problem for
  finding newest. Previous version = exact last-seen value (not sorted), so
  no semver issue there either. Good.
- **Go threat mismatch**: Go's dominant attack vector is typosquatting /
  impersonation of popular modules (boltdb-go, qmgo), NOT malicious updates
  to popular modules. The allowlist+diff model catches the latter but misses
  the former. Go-specific typosquat detection (watch for new packages with
  names close to popular ones) is a separate future mechanism.
- **Maven scans bytecode, not source**: fetches the main .jar (compiled),
  not -sources.jar (which isn't always published). Prefer -sources.jar when
  available — coarser analysis until then.
- **grepImports**: substring matching, not AST parsing. Per-ecosystem AST
  parsing would cut false positives.

## Hardening before "production-ready"
- Remove localhost dev origins from CORS allowlist (cmd/web/main.go),
  leaving only the grepwatch.com origins.
- Persist last-poll timestamp in the worker (or rely on watched_versions,
  which now serves a similar purpose).
- Cross-process SSE bridge (Postgres LISTEN/NOTIFY) so worker findings reach
  web-process browsers live in the two-service deploy.

## Deferred (dynamic feed — gated on resolvers being truthful)
- Stats counter (cumulative packages scanned, findings to date).
- Benign-activity ticker (sampled clean scans, requires tagged SSE envelope).
- Best built together once watchers produce real scan activity.