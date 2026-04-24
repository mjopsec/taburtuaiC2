export type AgentStatus  = 'online' | 'offline' | 'dormant'
export type CommandStatus = 'pending' | 'executing' | 'completed' | 'failed' | 'timeout' | 'cancelled'

export interface Agent {
  id:                 string
  hostname:           string
  username:           string
  os:                 string
  arch:               string
  ip:                 string
  pid:                number
  status:             AgentStatus
  last_seen:          string
  first_seen:         string
  check_in_interval:  number
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
  id:          string
  name:        string
  type:        string
  description: string
  downloads:   number
  created_at:  string
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
