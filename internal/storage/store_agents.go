package storage

import "database/sql"

// AgentRow is the flat database representation of an agent
type AgentRow struct {
	ID               string
	Hostname         string
	Username         string
	OS               string
	Architecture     string
	ProcessID        int
	ParentProcessID  int
	Privileges       string
	Status           string
	LastSeen         int64
	LastHeartbeat    int64
	FirstContact     int64
	TotalConnections int
	CmdsExecuted     int
	FilesTransferred int
	NetworkInfoJSON  string
	SystemInfoJSON   string
	SecurityInfoJSON string
	PerformanceJSON  string
	MetadataJSON     string
}

// AgentErrorRow is a single error event for an agent
type AgentErrorRow struct {
	AgentID     string
	ErrorType   string
	Message     string
	Command     string
	Severity    string
	Recoverable bool
	OccurredAt  int64
}

// UpsertAgent inserts or updates an agent record
func (s *Store) UpsertAgent(r AgentRow) error {
	_, err := s.db.Exec(`
	INSERT INTO agents
		(id,hostname,username,os,architecture,process_id,parent_process_id,
		 privileges,status,last_seen,last_heartbeat,first_contact,total_connections,
		 commands_executed,files_transferred,network_info,system_info,security_info,
		 performance,metadata)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(id) DO UPDATE SET
		hostname=excluded.hostname, username=excluded.username, os=excluded.os,
		architecture=excluded.architecture, process_id=excluded.process_id,
		parent_process_id=excluded.parent_process_id, privileges=excluded.privileges,
		status=excluded.status, last_seen=excluded.last_seen,
		last_heartbeat=excluded.last_heartbeat,
		total_connections=excluded.total_connections,
		commands_executed=excluded.commands_executed,
		files_transferred=excluded.files_transferred,
		network_info=excluded.network_info, system_info=excluded.system_info,
		security_info=excluded.security_info, performance=excluded.performance,
		metadata=excluded.metadata`,
		r.ID, r.Hostname, r.Username, r.OS, r.Architecture,
		r.ProcessID, r.ParentProcessID, r.Privileges, r.Status,
		r.LastSeen, r.LastHeartbeat, r.FirstContact,
		r.TotalConnections, r.CmdsExecuted, r.FilesTransferred,
		r.NetworkInfoJSON, r.SystemInfoJSON, r.SecurityInfoJSON,
		r.PerformanceJSON, r.MetadataJSON,
	)
	return err
}

// GetAgent fetches one agent by ID. Returns (row, false, nil) when not found.
func (s *Store) GetAgent(id string) (AgentRow, bool, error) {
	row := s.db.QueryRow(agentSelectSQL+` WHERE id=?`, id)
	r, err := scanAgent(row)
	if err == sql.ErrNoRows {
		return AgentRow{}, false, nil
	}
	return r, err == nil, err
}

// GetAllAgents returns every agent record
func (s *Store) GetAllAgents() ([]AgentRow, error) {
	rows, err := s.db.Query(agentSelectSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AgentRow
	for rows.Next() {
		r, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// DeleteAgent removes an agent and its errors (cascade)
func (s *Store) DeleteAgent(id string) error {
	_, err := s.db.Exec(`DELETE FROM agents WHERE id=?`, id)
	return err
}

// AppendAgentError inserts one error record for an agent
func (s *Store) AppendAgentError(r AgentErrorRow) error {
	rec := 0
	if r.Recoverable {
		rec = 1
	}
	_, err := s.db.Exec(`
	INSERT INTO agent_errors (agent_id,error_type,message,command,severity,recoverable,occurred_at)
	VALUES (?,?,?,?,?,?,?)`,
		r.AgentID, r.ErrorType, r.Message, r.Command, r.Severity, rec, r.OccurredAt)
	return err
}

// GetAgentErrors returns the most recent limit errors for an agent
func (s *Store) GetAgentErrors(agentID string, limit int) ([]AgentErrorRow, error) {
	rows, err := s.db.Query(`
	SELECT agent_id,error_type,message,command,severity,recoverable,occurred_at
	FROM agent_errors WHERE agent_id=? ORDER BY occurred_at DESC LIMIT ?`,
		agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AgentErrorRow
	for rows.Next() {
		var r AgentErrorRow
		var rec int
		if err := rows.Scan(&r.AgentID, &r.ErrorType, &r.Message, &r.Command,
			&r.Severity, &rec, &r.OccurredAt); err != nil {
			return nil, err
		}
		r.Recoverable = rec != 0
		result = append(result, r)
	}
	return result, rows.Err()
}

// PruneAgentErrors deletes old errors beyond the keep limit for an agent
func (s *Store) PruneAgentErrors(agentID string, keep int) error {
	_, err := s.db.Exec(`
	DELETE FROM agent_errors WHERE agent_id=? AND id NOT IN (
		SELECT id FROM agent_errors WHERE agent_id=? ORDER BY occurred_at DESC LIMIT ?
	)`, agentID, agentID, keep)
	return err
}

// ── helpers ───────────────────────────────────────────────────────────────────

const agentSelectSQL = `
SELECT id,hostname,username,os,architecture,process_id,parent_process_id,
       privileges,status,last_seen,last_heartbeat,first_contact,total_connections,
       commands_executed,files_transferred,network_info,system_info,security_info,
       performance,metadata
FROM agents`

type agentScanner interface {
	Scan(dest ...any) error
}

func scanAgent(row agentScanner) (AgentRow, error) {
	var r AgentRow
	err := row.Scan(
		&r.ID, &r.Hostname, &r.Username, &r.OS, &r.Architecture,
		&r.ProcessID, &r.ParentProcessID, &r.Privileges, &r.Status,
		&r.LastSeen, &r.LastHeartbeat, &r.FirstContact,
		&r.TotalConnections, &r.CmdsExecuted, &r.FilesTransferred,
		&r.NetworkInfoJSON, &r.SystemInfoJSON, &r.SecurityInfoJSON,
		&r.PerformanceJSON, &r.MetadataJSON,
	)
	return r, err
}
