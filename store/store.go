package store

import (
	"context"
	"encoding/json"
	"fmt"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/grepstrength/grepwatch/model"
)

//wraps a Postgres connection pool and is the only file used to talk to the DB. by keeping all the SQL behind this means the worker and webserver nver see raw queries... changing the DB or table layout only affects this file
type Store struct { 	
	pool *pgxpool.Pool
}

//Stats is the read-model returne dby the Stats method and serialized straight to JSON by the upcoming /api/stats endpoint
type Stats struct {
	PackagesWatched	int64 `json:"packages_watched"` //how many distinct packages that are tracked
	VersionsScanned	int64 `json:"versions_scanned"` //cumulative difs
	FindingsTotal	int64 `json:"findings_total"`
}

/*
New creates a Store by connecting to Postgres using the given connection string (a standard postgres:// URL, which Railway provides as an env var)
this also ensures the findings table exists
the caller gets a fully read-to-use Store or an error, but never a half-initialized one
*/
func New(ctx context.Context, connString string) (*Store, error) {

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil { //forces an actual connection to verify the DB is reachable
		pool.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}
	s := &Store{pool: pool} //wraps the pool in our Store


	if err := s.ensureSchema(ctx); err != nil { //ensure the schema exists before returning
		pool.Close()
		return nil, fmt.Errorf("store: ensure schema: %w", err)
	}

	return s, nil
}


//this creates the findings tabl if it doesn't already exist
func (s *Store) ensureSchema(ctx context.Context) error {

	const schema = `
		CREATE TABLE IF NOT EXISTS findings (
			id           BIGSERIAL PRIMARY KEY,
			ecosystem    TEXT        NOT NULL,
			name         TEXT        NOT NULL,
			version      TEXT        NOT NULL,
			prev_version TEXT        NOT NULL,
			severity     INTEGER     NOT NULL,
			signals      JSONB       NOT NULL,
			analyzed_at  TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS watched_versions ( 
			ecosystem    TEXT        NOT NULL,
			name         TEXT        NOT NULL,
			last_version TEXT        NOT NULL,
			updated_at   TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (ecosystem, name) 
		);
		CREATE TABLE IF NOT EXISTS scan_stats (
			id					INTEGER PRIMARY KEY DEFAULT 1,
			versions_scanned 	BIGINT NOT NULL DEFAULT 0,
			CONSTRAINT single_row CHECK (id = 1)
		);
		INSERT INTO scan_stats (id, versions_scanned)
		VALUES (1, 0)
		ON CONFLICT (id) DO NOTHING;
		CREATE INDEX IF NOT EXISTS idx_findings_analyzed_at
			ON findings (analyzed_at DESC);

		CREATE INDEX IF NOT EXISTS idx_findings_severity
			ON findings (severity DESC);
	`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("create findings schema: %w", err)
	}

	return nil
}
//this persists a single finding, and its called by the worker immediately afterthe diff engine produces a finding worth keeping (any with at least one signal)
func (s *Store) Save(ctx context.Context, f *model.Finding) (int64, error) {
	signalsJSON, err := json.Marshal(f.Signals)
	if err != nil {
		return 0, fmt.Errorf("store: marshal signals: %w", err)
	}

	const query = `
		INSERT INTO findings
			(ecosystem, name, version, prev_version, severity, signals, analyzed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id;
	`
	var id int64
	err = s.pool.QueryRow(ctx, query,
		string(f.Package.Ecosystem),
		f.Package.Name,
		f.Package.Version,
		f.PrevVersion,
		int(f.Severity),
		signalsJSON,
		f.AnalyzedAt,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: insert finding: %w", err)
	}

	return id, nil
}
/*this returns the most recent version on record for a watched package

if you have never seen a given package before, it returns an empty string
the caller treats "" as "brand new with nothing to compare against yet"
then records the current version without diffing
*/
func (s *Store) GetLastVersion(ctx context.Context, ecosystem model.Ecosystem, name string) (string, error) {
	const query = `
		SELECT last_version
		FROM watched_versions
		WHERE ecosystem = $1 AND name = $2;
		`
	var version string
	err := s.pool.QueryRow(ctx, query, string(ecosystem), name).Scan(&version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) { //translates the response to an empty string so the caller does not have to import pgx for nothing found
			return "", nil
		}
		return "", fmt.Errorf("store: get last version: %w", err)
	}
	return version, nil
}

//this reuns the most recent findings, newest first, up to the given limit 
func (s *Store) Recent(ctx context.Context, limit int) ([]model.Finding, error) {

	if limit <= 0 || limit > 200 {
		limit = 50
	}

	const query = ` 
		SELECT ecosystem, name, version, prev_version, severity, signals, analyzed_at
		FROM findings
		ORDER BY analyzed_at DESC
		LIMIT $1;
	`
	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("store: query recent: %w", err)
	}
	defer rows.Close()

	findings := make([]model.Finding, 0, limit) //pre-allocate with capacity limit since the maximum row count
	for rows.Next() {
		var (
			f           model.Finding
			ecosystem   string 
			severity    int
			signalsJSON []byte 
		)
		if err := rows.Scan( //scan copies into the rowes columns in to our variables in column order
			&ecosystem,
			&f.Package.Name,
			&f.Package.Version,
			&f.PrevVersion,
			&severity,
			&signalsJSON,
			&f.AnalyzedAt,
		); err != nil {
			return nil, fmt.Errorf("store: scan finding: %w", err)
		}
		f.Package.Ecosystem = model.Ecosystem(ecosystem)
		f.Severity = model.Severity(severity)
		if err := json.Unmarshal(signalsJSON, &f.Signals); err != nil { //unmarhal the JSON signals blob back into the Signals slice
			return nil, fmt.Errorf("store: unmarshal signals: %w", err)
		}

		findings = append(findings, f)
	}

	if err := rows.Err(); err != nil { //reports any error that occurred during iteration
		return nil, fmt.Errorf("store: iterate rows: %w", err)
	}

	return findings, nil
}
//records the latest version seen for a watched package. inserts a new row if the package is new or updates the existing row if its been seen before
func (s *Store) SetLastVersion(ctx context.Context, ecosystem model.Ecosystem, name, version string) error {
	const query = `
		INSERT INTO watched_versions (ecosystem, name, last_version, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (ecosystem, name)
		DO UPDATE SET last_version = EXCLUDED.last_version, updated_at = NOW();
	`

	_, err := s.pool.Exec(ctx, query,
		string(ecosystem),
		name,
		version,
	)
	if err != nil {
		return fmt.Errorf("store: set last version: %w", err)
	}

	return nil
}

/*
IncrementVersionsScanned adds n to the running counter
its called by the worker's analyzeOne (cmd/worker/main.go) once per successful diff, so the number climbs steadily and never resets
*/
func (s *Store) IncrementVersionsScanned(ctx context.Context, n int) error {
	const query = `
		UPDATE scan_stats
		SET versions_scanned = versions_scanned + $1
		WHERE id = 1;
	`
	if _, err := s.pool.Exec(ctx, query, n); err != nil { //Exec runs a statement that returns no rows
		return fmt.Errorf("store: increment versions scanned: %w", err)
	}
	return nil
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var out Stats //zero valued struct
	//holds one row per package thats tracked, so COUNT(*) of that table is the number of packages watched
	const watchedQuery = `SELECT COUNT(*) FROM watched_versions;`
	if err := s.pool.QueryRow(ctx, watchedQuery).Scan(&out.PackagesWatched); err != nil {
		return Stats{}, fmt.Errorf("store: count watched: %w", err) //return an empty Stats on any failure so the caller never gets incompleted data
	}
	//the single running counter row that's seeded (id = 1)
	const scannedQuery = `SELECT versions_scanned FROM scan_stats WHERE id = 1;`
	if err := s.pool.QueryRow(ctx, scannedQuery).Scan(&out.VersionsScanned); err != nil {
		return Stats{}, fmt.Errorf("store: read versions scanned: %w", err)
	}
	//one row per stored findnig so COUNT() is the total
	const findingsQuery = `SELECT COUNT(*) FROM findings;`
	if err := s.pool.QueryRow(ctx, findingsQuery).Scan(&out.FindingsTotal); err != nil {
		return Stats{}, fmt.Errorf("store: count findins: %w", err)
	}
	return out, nil //all three fields populated > hand the struct back to the caller
}

func (s *Store) Close() {
	s.pool.Close()
}


