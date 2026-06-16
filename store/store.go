package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/grepstrength/grepwatch/model"
)

//wraps a Postgres connection pool and is the only file used to talk to the DB. by keeping all the SQL behind this means the worker and webserver nver see raw queries... changing the DB or table layout only affects this file
type Store struct { 	
	pool *pgxpool.Pool
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
func (s *Store) Close() {
	s.pool.Close()
}


