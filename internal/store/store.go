// Package store keeps portal metadata (the audit log) in SQLite.
// Certificates themselves live in Kubernetes; keys never come here.
package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type Event struct {
	Time   time.Time
	Action string
	Target string
	Detail string
	Remote string
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY,
		ts INTEGER NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		remote TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		return nil, err
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Log(action, target, detail, remote string) error {
	_, err := s.db.Exec(`INSERT INTO audit (ts, action, target, detail, remote) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), action, target, detail, remote)
	return err
}

// Events returns the newest events first, optionally filtered by target or action substring.
func (s *Store) Events(q string, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT ts, action, target, detail, remote FROM audit
		WHERE ? = '' OR target LIKE '%' || ? || '%' OR action LIKE '%' || ? || '%'
		ORDER BY id DESC LIMIT ?`, q, q, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&ts, &e.Action, &e.Target, &e.Detail, &e.Remote); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
