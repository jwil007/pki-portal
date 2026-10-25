package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Hook is a delivery hook attached to one certificate. Config holds the
// driver's settings; TokenHash is only used by pull hooks (sha256 of the token).
type Hook struct {
	ID          int64
	CertID      string
	Type        string
	Name        string
	Config      map[string]string
	TokenHash   string
	Enabled     bool
	Created     time.Time
	LastSerial  string // serial last delivered; a different current serial means "deliver"
	LastRun     time.Time
	LastOK      bool
	LastMessage string
	Failures    int
	NextAttempt time.Time
}

func migrateHooks(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS hooks (
		id INTEGER PRIMARY KEY,
		cert_id TEXT NOT NULL,
		type TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		config TEXT NOT NULL DEFAULT '{}',
		token_hash TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		created INTEGER NOT NULL,
		last_serial TEXT NOT NULL DEFAULT '',
		last_run INTEGER NOT NULL DEFAULT 0,
		last_ok INTEGER NOT NULL DEFAULT 0,
		last_message TEXT NOT NULL DEFAULT '',
		failures INTEGER NOT NULL DEFAULT 0,
		next_attempt INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS hooks_cert ON hooks(cert_id);
	CREATE INDEX IF NOT EXISTS hooks_token ON hooks(token_hash);`)
	return err
}

const hookCols = `id, cert_id, type, name, config, token_hash, enabled, created, last_serial, last_run, last_ok, last_message, failures, next_attempt`

func unixOrZero(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0)
}

func scanHook(row interface{ Scan(...any) error }) (*Hook, error) {
	var h Hook
	var cfg string
	var created, lastRun, next int64
	if err := row.Scan(&h.ID, &h.CertID, &h.Type, &h.Name, &cfg, &h.TokenHash, &h.Enabled, &created,
		&h.LastSerial, &lastRun, &h.LastOK, &h.LastMessage, &h.Failures, &next); err != nil {
		return nil, err
	}
	h.Config = map[string]string{}
	json.Unmarshal([]byte(cfg), &h.Config)
	h.Created, h.LastRun, h.NextAttempt = time.Unix(created, 0), unixOrZero(lastRun), unixOrZero(next)
	return &h, nil
}

func (s *Store) hooksWhere(where string, args ...any) ([]*Hook, error) {
	rows, err := s.db.Query(`SELECT `+hookCols+` FROM hooks `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Hook
	for rows.Next() {
		h, err := scanHook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) AddHook(h *Hook) error {
	cfg, _ := json.Marshal(h.Config)
	res, err := s.db.Exec(`INSERT INTO hooks (cert_id, type, name, config, token_hash, enabled, created, last_serial) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		h.CertID, h.Type, h.Name, string(cfg), h.TokenHash, time.Now().Unix(), h.LastSerial)
	if err != nil {
		return err
	}
	h.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) Hook(id int64) (*Hook, error) {
	h, err := scanHook(s.db.QueryRow(`SELECT `+hookCols+` FROM hooks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("hook not found")
	}
	return h, err
}

func (s *Store) HooksFor(certID string) ([]*Hook, error) {
	return s.hooksWhere(`WHERE cert_id = ?`, certID)
}

func (s *Store) AllHooks() ([]*Hook, error) { return s.hooksWhere(``) }

// HookByToken finds the pull hook for a certificate by token hash.
func (s *Store) HookByToken(certID, tokenHash string) (*Hook, error) {
	hs, err := s.hooksWhere(`WHERE cert_id = ? AND token_hash = ? AND token_hash != '' AND enabled = 1`, certID, tokenHash)
	if err != nil || len(hs) == 0 {
		return nil, errors.New("invalid token")
	}
	return hs[0], nil
}

// RecordRun saves the outcome of a delivery. On success the serial is marked
// delivered; on failure the next attempt backs off exponentially (max 1h).
func (s *Store) RecordRun(h *Hook, serial string, runErr error) error {
	now := time.Now()
	if runErr == nil {
		_, err := s.db.Exec(`UPDATE hooks SET last_serial = ?, last_run = ?, last_ok = 1, last_message = 'delivered', failures = 0, next_attempt = 0 WHERE id = ?`,
			serial, now.Unix(), h.ID)
		return err
	}
	backoff := time.Minute << min(h.Failures, 6)
	_, err := s.db.Exec(`UPDATE hooks SET last_run = ?, last_ok = 0, last_message = ?, failures = failures + 1, next_attempt = ? WHERE id = ?`,
		now.Unix(), runErr.Error(), now.Add(backoff).Unix(), h.ID)
	return err
}

func (s *Store) DeleteHook(id int64) error {
	_, err := s.db.Exec(`DELETE FROM hooks WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteHooksFor(certID string) error {
	_, err := s.db.Exec(`DELETE FROM hooks WHERE cert_id = ?`, certID)
	return err
}

// GitOps download tracking: which serial of a Git-managed certificate was last
// downloaded, so the UI can flag "renewed since your last download".

func migrateGitOps(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS gitops_downloads (
		cert TEXT PRIMARY KEY,
		serial TEXT NOT NULL,
		at INTEGER NOT NULL
	)`)
	return err
}

func (s *Store) RecordGitOpsDownload(cert, serial string) error {
	_, err := s.db.Exec(`INSERT INTO gitops_downloads (cert, serial, at) VALUES (?, ?, ?)
		ON CONFLICT(cert) DO UPDATE SET serial = excluded.serial, at = excluded.at`, cert, serial, time.Now().Unix())
	return err
}

// LastGitOpsDownload returns the serial and time of the last download, if any.
func (s *Store) LastGitOpsDownload(cert string) (string, time.Time) {
	var serial string
	var at int64
	if err := s.db.QueryRow(`SELECT serial, at FROM gitops_downloads WHERE cert = ?`, cert).Scan(&serial, &at); err != nil {
		return "", time.Time{}
	}
	return serial, time.Unix(at, 0)
}
