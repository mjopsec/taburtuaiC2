export type AgentStatus   = 'online' | 'offline' | 'dormant'
export type CommandStatus = 'pending' | 'executing' | 'completed' | 'failed' | 'timeout' | 'cancelled'

export interface Agent {
  id:                string
  hostname:          string
  username:          string
  os:                string
  arch:              string
  ip:                string
  pid:               number
  privileges:        string   // "admin" | "user"
  status:            AgentStatus
  last_seen:         string
  first_seen:        string
  check_in_interval: number
}

export interface Command {
  id:         string
  agent_id:   string
  op:         string
  status:     CommandStatus
  output:     string
  error?:     string
  created_at: string
  updated_at: string
}

export interface Stats {
  agents?: {
    total:   number
    online:  number
    offline: number
    dormant: number
  }
  commands?: {
    total:     number
    pending:   number
    executing: number
    completed: number
    failed:    number
  }
  uptime?: number
}

export interface Stage {
  token:       string
  format:      string
  arch:        string
  os_target:   string
  description: string
  size?:       number
  created_at:  string
  expires_at?: string
  used:        boolean
  used_at?:    string
  used_by_ip?: string
}

export interface LogEntry {
  level:    string
  ts:       string
  message:  string
  agent_id?: string
}

export interface ApiResponse<T = unknown> {
  success?: boolean
  message?: string
  data?:    T
  error?:   string
}
