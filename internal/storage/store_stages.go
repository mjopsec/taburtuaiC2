package storage

import (
	"database/sql"
	"time"
)

// StageRow is the DB representation of a staged payload
type StageRow struct {
	Token       string
	Payload     []byte // AES-256-GCM encrypted: nonce(12)|ciphertext
	Format      string // exe|shellcode|dll
	Arch        string // amd64|x86
	OSTarget    string // windows|linux|darwin
	CreatedAt   int64
	ExpiresAt   int64  // 0 = no expiry
	Used        int    // 0=unused, 1=used
	UsedAt      int64
	UsedByIP    string
	Description string
}

func (s *Store) InsertStage(r StageRow) error {
	_, err := s.db.Exec(`
	INSERT INTO stages
		(token, payload, format, arch, os_target, created_at, expires_at,
		 used, used_at, used_by_ip, description)
	VALUES (?,?,?,?,?,?,?,0,0,'',?)`,
		r.Token, r.Payload, r.Format, r.Arch, r.OSTarget,
		r.CreatedAt, r.ExpiresAt, r.Description,
	)
	return err
}

func (s *Store) GetStage(token string) (StageRow, bool, error) {
	row := s.db.QueryRow(`
	SELECT token, payload, format, arch, os_target,
	       created_at, expires_at, used, used_at, used_by_ip, description
	FROM stages WHERE token=?`, token)
	var r StageRow
	err := row.Scan(
		&r.Token, &r.Payload, &r.Format, &r.Arch, &r.OSTarget,
		&r.CreatedAt, &r.ExpiresAt, &r.Used, &r.UsedAt, &r.UsedByIP, &r.Description,
	)
	if err == sql.ErrNoRows {
		return StageRow{}, false, nil
	}
	return r, err == nil, err
}

func (s *Store) MarkStageUsed(token, ip string) error {
	_, err := s.db.Exec(
		`UPDATE stages SET used=1, used_at=?, used_by_ip=? WHERE token=?`,
		time.Now().Unix(), ip, token,
	)
	return err
}

func (s *Store) DeleteStage(token string) error {
	_, err := s.db.Exec(`DELETE FROM stages WHERE token=?`, token)
	return err
}

// ListStages returns all stages without the (potentially large) payload bytes.
func (s *Store) ListStages() ([]StageRow, error) {
	rows, err := s.db.Query(`
	SELECT token, format, arch, os_target,
	       created_at, expires_at, used, used_at, used_by_ip, description
	FROM stages ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []StageRow
	for rows.Next() {
		var r StageRow
		if err := rows.Scan(
			&r.Token, &r.Format, &r.Arch, &r.OSTarget,
			&r.CreatedAt, &r.ExpiresAt, &r.Used, &r.UsedAt, &r.UsedByIP, &r.Description,
		); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) CleanExpiredStages() (int, error) {
	res, err := s.db.Exec(
		`DELETE FROM stages WHERE expires_at > 0 AND expires_at < ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
