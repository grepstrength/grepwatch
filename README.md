![alt text](grepwatch-final.png)

# grepWatch

**Catch malicious dependency updates before they reach production!**

*Forget AI! 2026 is the year of the supply chain attack!*

grepWatch is an open-source dependency behavioral diff engine. It watches package registeries across six ecosystems and flags when a new release *changes* in suspicious ways. (e.g. new outbound network calls, added obfuscation, high-entropy strings consistent with encoded payloads, and install-time execution hooks)

Detects malicious changes in packages by diffing versions over time - catching supply chain attacks before you ship them.

Most supply-chain tools answer *"is this package already known to be bad?"*. They match against lists of already-discovered malware. grepWatch answers a different question: *"did this package just change in a way that looks malicious?"* It compares each new release against the previous one, so it can flag a freshly-compromised version of a trusted, popular package the moment it ships — before it lands on anyone's known-bad list.

This checks across the following ecosystems:
- npm
- PyPI
- Go
- Cargo
- Maven
- NuGet

*This entire repo is extra verbose with comments because I'm tired of relearning how to code every few months...*

⚠️ **ATTENTION**: I'm still actively tuning the findings in `diff/grep.go`. 

## Hosted version

A hosted instance runs at **[grepwatch.com](https://grepwatch.com)** with a live feed of findings — no setup required. Self-hosting is fully supported and documented below and throughout the repo for anyone who wants to run their own instance.

Subscribe to findings via **RSS** at [grepwatch.com/feed.xml](https://grepwatch.com/feed.xml) to pull them into a feed reader, Slack, or your SIEM — no browser tab required.

## How it works

grepWatch runs as two services that share a Postgres database:

- **Worker**: on a fixed interval, each ecosystem watcher checks a curated allowlist of popular packages for a new version. When a package's latest version differs from the one grepWatch last saw, the worker fetches the source of both the new and previous releases, runs static-analysis checks against the diff, scores anything suspicious, and stores the finding.
- **Web**: serves a REST API and a Server-Sent Events stream that powers the live feed of findings.

## Self-hosting

grepWatch is two long-running Go services sharing one Postgres database:
- the **worker** polls package registries and writes findings,
- the **web** service exposes the REST API, the SSE live feed, and the RSS feed.

### Requirements
- Go 1.25+
- PostgreSQL 14+

### 1. Database
Create a database and note its connection string:
```bash
createdb grepwatch
# postgres://user:pass@localhost:5432/grepwatch
```
Both services create their tables (`findings`, `watched_versions`) on first run — no migrations to run.

### 2. Configuration
Both services read from the environment:

| Variable | Service | Required | Description |
|---|---|---|---|
| `DATABASE_URL` | both | yes | Postgres connection string |
| `PORT` | web | no | Web server port (default 8080) |

The allowlist generator (`cmd/genlists`) also reads `GREPWATCH_CONTACT_EMAIL` — the contact address sent to ecosyste.ms when fetching popular-package lists.

### 3. Choose what to watch
The worker only scans the packages listed in `data/<ecosystem>.json` — one JSON
array of names per ecosystem. This is the main thing you'll customize:

- **Watch your own dependencies**: replace the contents of `data/npm.json`,
  `data/pypi.json`, etc. with the packages you actually ship. They're plain
  JSON arrays of names (`["express", "lodash"]`). Maven entries are
  `group:artifact`; Go entries are full module paths.
- **Or regenerate the top-1000 popular lists**:
```bash
  GREPWATCH_CONTACT_EMAIL=you@example.com go run ./cmd/genlists
```

> ⚠️ The worker loads these files by **relative path** (`data/...`), so start it
> from the repository root. Run it from anywhere else and the allowlists load
> empty and nothing is scanned — with no error message.

### 4. Run
Quick look (development):
```bash
DATABASE_URL=postgres://... go run ./cmd/worker      # from the repo root
DATABASE_URL=postgres://... PORT=8080 go run ./cmd/web
```

For real hosting, build binaries and run them under a process manager
(systemd, Docker, etc.) so they restart on failure:
```bash
go build -o grepwatch-worker ./cmd/worker
go build -o grepwatch-web ./cmd/web
```
The web service exposes `GET /healthz` (returns `ok`) for uptime checks and
container health probes.

### 5. Point the API at your domain
The web service restricts cross-origin requests to an allowlist hardcoded in
`cmd/web/main.go`. Edit `allowedOrigins` to your own domain:
```go
var allowedOrigins = map[string]bool{
    "https://yourdomain.com": true,
}
```

### Tuning & honest caveats
- **Poll interval**: the worker re-checks every watched package every 30 minutes
  (`pollInterval` in `cmd/worker/main.go`). A large allowlist across six
  registries is thousands of requests per cycle — raise the interval for big
  lists, and respect each registry's crawler policy (crates.io's in particular).
- **Live feed in a split deploy**: with the worker and web as separate processes,
  new findings are written to Postgres and show up on page load, but are **not
  yet pushed** over the SSE stream — the two processes have separate in-memory
  broadcasters. Cross-process push (Postgres `LISTEN/NOTIFY`) is on the roadmap;
  until then, the live feed is truly live only when worker and web share a process.

### Frontend (optional)
The web service is a JSON/SSE/RSS API. The UI at grepwatch.com is a separate
React app; point its `VITE_API_BASE` at your web service to run your own.

## License

AGPL-3.0 — see [LICENSE](LICENSE). You're free to self-host and modify. If you run a modified version as a network service, the AGPL requires you to make your source available to its users.
