package storage

import (
	"database/sql"
	"time"
)

// CommandRow is the flat database representation of a command
type CommandRow struct {
	ID              string
	AgentID         string
	Command         string
	ArgsJSON        string
	WorkingDir      string
	Timeout         int
	Status          string
	ExitCode        int
	Output          string
	Error           string
	MetadataJSON    string
	OperationType   string
	SourcePath      string
	DestinationPath string
	FileContent     []byte
	IsEncrypted     bool
	ProcessName     string
	ProcessID       int
	ProcessPath     string
	ProcessArgsJSON string
	PersistMethod   string
	PersistName     string
	CreatedAt       int64
	ExecutedAt      int64
	CompletedAt     int64
	PayloadJSON     string
}

// InsertCommand inserts a new command record
func (s *Store) InsertCommand(r CommandRow) error {
	enc := boolToInt(r.IsEncrypted)
	_, err := s.db.Exec(`
	INSERT INTO commands
		(id,agent_id,command,args,working_dir,timeout,status,exit_code,output,error,
		 metadata,operation_type,source_path,destination_path,file_content,is_encrypted,
		 process_name,process_id,process_path,process_args,persist_method,persist_name,
		 created_at,executed_at,completed_at,payload_json)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.AgentID, r.Command, r.ArgsJSON, r.WorkingDir, r.Timeout,
		r.Status, r.ExitCode, r.Output, r.Error, r.MetadataJSON,
		r.OperationType, r.SourcePath, r.DestinationPath, r.FileContent, enc,
		r.ProcessName, r.ProcessID, r.ProcessPath, r.ProcessArgsJSON,
		r.PersistMethod, r.PersistName, r.CreatedAt, r.ExecutedAt, r.CompletedAt,
		r.PayloadJSON,
	)
	return err
}

// UpdateCommandStatus updates only the mutable result fields after execution
func (s *Store) UpdateCommandStatus(r CommandRow) error {
	_, err := s.db.Exec(`
	UPDATE commands SET
		status=?, exit_code=?, output=?, error=?,
		executed_at=?, completed_at=?
	WHERE id=?`,
		r.Status, r.ExitCode, r.Output, r.Error,
		r.ExecutedAt, r.CompletedAt, r.ID,
	)
	return err
}

// GetCommand fetches a command by ID. Returns (row, false, nil) when not found.
func (s *Store) GetCommand(id string) (CommandRow, bool, error) {
	row := s.db.QueryRow(cmdSelectSQL+` WHERE id=?`, id)
	r, err := scanCommand(row)
	if err == sql.ErrNoRows {
		return CommandRow{}, false, nil
	}
	return r, err == nil, err
}

// GetAgentExecutingCommand returns the single 'executing' command for an agent, if any
func (s *Store) GetAgentExecutingCommand(agentID string) (CommandRow, bool, error) {
	row := s.db.QueryRow(cmdSelectSQL+` WHERE agent_id=? AND status='executing' LIMIT 1`, agentID)
	r, err := scanCommand(row)
	if err == sql.ErrNoRows {
		return CommandRow{}, false, nil
	}
	return r, err == nil, err
}

// GetAgentNextPending returns the oldest pending command for an agent
func (s *Store) GetAgentNextPending(agentID string) (CommandRow, bool, error) {
	row := s.db.QueryRow(cmdSelectSQL+` WHERE agent_id=? AND status='pending' ORDER BY created_at ASC LIMIT 1`, agentID)
	r, err := scanCommand(row)
	if err == sql.ErrNoRows {
		return CommandRow{}, false, nil
	}
	return r, err == nil, err
}

// GetAgentCommands returns commands for an agent filtered by status and limited in count
func (s *Store) GetAgentCommands(agentID, status string, limit int) ([]CommandRow, error) {
	if status == "" {
		return s.queryCommands(cmdSelectSQL+` WHERE agent_id=? ORDER BY created_at DESC LIMIT ?`, agentID, limit)
	}
	return s.queryCommands(cmdSelectSQL+` WHERE agent_id=? AND status=? ORDER BY created_at DESC LIMIT ?`, agentID, status, limit)
}

// GetAllCommands returns recent commands across all agents, optionally filtered by status
func (s *Store) GetAllCommands(status string, limit int) ([]CommandRow, error) {
	if status == "" {
		return s.queryCommands(cmdSelectSQL+` ORDER BY created_at DESC LIMIT ?`, limit)
	}
	return s.queryCommands(cmdSelectSQL+` WHERE status=? ORDER BY created_at DESC LIMIT ?`, status, limit)
}

// GetAgentQueueSize returns the count of pending commands for an agent
func (s *Store) GetAgentQueueSize(agentID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM commands WHERE agent_id=? AND status='pending'`, agentID).Scan(&count)
	return count, err
}

// CancelAgentPendingCommands marks all pending commands for an agent as cancelled
func (s *Store) CancelAgentPendingCommands(agentID string) (int, error) {
	res, err := s.db.Exec(`
	UPDATE commands SET status='cancelled', completed_at=?
	WHERE agent_id=? AND status='pending'`,
		time.Now().Unix(), agentID,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GetCommandStats returns aggregate counts grouped by agent and status
func (s *Store) GetCommandStats() (map[string]interface{}, error) {
	rows, err := s.db.Query(`SELECT agent_id, status, COUNT(*) FROM commands GROUP BY agent_id, status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type stat struct{ queued, active, completed int }
	byAgent := make(map[string]*stat)
	for rows.Next() {
		var agentID, status string
		var count int
		if err := rows.Scan(&agentID, &status, &count); err != nil {
			return nil, err
		}
		if byAgent[agentID] == nil {
			byAgent[agentID] = &stat{}
		}
		switch status {
		case "pending":
			byAgent[agentID].queued += count
		case "executing":
			byAgent[agentID].active += count
		default:
			byAgent[agentID].completed += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalQ, totalA, totalC := 0, 0, 0
	agentStats := make(map[string]map[string]int, len(byAgent))
	for id, st := range byAgent {
		totalQ += st.queued
		totalA += st.active
		totalC += st.completed
		agentStats[id] = map[string]int{
			"queued": st.queued, "active": st.active, "completed": st.completed,
		}
	}
	return map[string]interface{}{
		"total_queued":    totalQ,
		"total_active":    totalA,
		"total_completed": totalC,
		"by_agent":        agentStats,
		"total_agents":    len(agentStats),
		"timestamp":       time.Now().Format(time.RFC3339),
	}, nil
}

// CleanOldCommands deletes completed/failed/cancelled commands older than olderThan
func (s *Store) CleanOldCommands(olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	res, err := s.db.Exec(`
	DELETE FROM commands
	WHERE completed_at > 0 AND completed_at < ?
	  AND status NOT IN ('pending','executing')`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

const cmdSelectSQL = `
SELECT id,agent_id,command,args,working_dir,timeout,status,exit_code,
       output,error,metadata,operation_type,source_path,destination_path,file_content,
       is_encrypted,process_name,process_id,process_path,process_args,
       persist_method,persist_name,created_at,executed_at,completed_at,
       COALESCE(payload_json,'{}')
FROM commands`

type cmdScanner interface {
	Scan(dest ...any) error
}

func scanCommand(row cmdScanner) (CommandRow, error) {
	var r CommandRow
	var enc int
	err := row.Scan(
		&r.ID, &r.AgentID, &r.Command, &r.ArgsJSON,
		&r.WorkingDir, &r.Timeout, &r.Status, &r.ExitCode,
		&r.Output, &r.Error, &r.MetadataJSON, &r.OperationType,
		&r.SourcePath, &r.DestinationPath, &r.FileContent, &enc,
		&r.ProcessName, &r.ProcessID, &r.ProcessPath, &r.ProcessArgsJSON,
		&r.PersistMethod, &r.PersistName,
		&r.CreatedAt, &r.ExecutedAt, &r.CompletedAt,
		&r.PayloadJSON,
	)
	r.IsEncrypted = enc != 0
	return r, err
}

func (s *Store) queryCommands(query string, args ...any) ([]CommandRow, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []CommandRow
	for rows.Next() {
		r, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
