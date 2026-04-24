import axios from 'axios'
import type { Agent, Command, Stats, Stage, LogEntry } from './types'

// Wrapper shape the Go server always returns
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
    http.get<Envelope<Command & {
      output?: string; error?: string; status?: string
    }>>(`/command/${id}/status`),

  list: (params: { agent_id?: string; status?: string; limit?: number }) =>
    http.get<Envelope<{ commands?: Command[]; count?: number }>>(
      params.agent_id ? `/agent/${params.agent_id}/commands` : '/commands',
      { params: { status: params.status, limit: params.limit } }
    ),

  stats: () =>
    http.get<Envelope<Stats>>('/queue/stats'),
}

// ── Server ──────────────────────────────────────────────────────────────────
export const serverApi = {
  stats:  () =>
    http.get<Envelope<Stats>>('/stats'),
  health: () =>
    http.get<Envelope>('/health'),
  logs: (params: { level?: string; limit?: number }) =>
    http.get<Envelope<{ logs?: LogEntry[] }>>('/logs', { params }),
}

// ── Stages ──────────────────────────────────────────────────────────────────
export const stageApi = {
  list:   () =>
    http.get<Envelope<{ stages?: Stage[] }>>('/stages'),
  create: (data: { name: string; type: string; description?: string }) =>
    http.post<Envelope<Stage>>('/stage', data),
  update: (id: string, data: Partial<Stage>) =>
    http.put<Envelope<Stage>>(`/stage/${id}`, data),
  delete: (id: string) =>
    http.delete<Envelope>(`/stage/${id}`),
}

// ── Team ────────────────────────────────────────────────────────────────────
export const teamApi = {
  operators: () => http.get<Envelope>('/team/operators'),
}

export default http
