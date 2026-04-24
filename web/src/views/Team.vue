<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">Team Server</div>
        <div class="page-desc">Multi-operator coordination and live event feed</div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-ghost btn-sm" @click="showRegister = true">+ Register Operator</button>
        <div :class="['sse-indicator', sseConnected ? 'connected' : 'disconnected']">
          <span class="badge-dot" :style="`background:${sseConnected ? 'var(--green)' : 'var(--red)'};animation:${sseConnected ? 'pulse-glow 2s infinite' : 'none'}`" />
          {{ sseConnected ? 'Live' : 'Disconnected' }}
        </div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:300px 1fr;gap:16px;align-items:start">

      <!-- Left column -->
      <div style="display:flex;flex-direction:column;gap:12px">

        <!-- Operators -->
        <div class="card">
          <div class="card-header" style="justify-content:space-between">
            <span class="card-title">Operators Online</span>
            <span style="font-size:11px;color:var(--text-muted)">{{ operators.length }}</span>
          </div>
          <div class="card-body" style="padding:0">
            <div v-if="!operators.length" class="empty-state" style="padding:24px">
              <div style="font-size:13px">No operators registered</div>
            </div>
            <div v-for="op in operators" :key="op.id"
                 style="padding:10px 14px;border-bottom:1px solid var(--border-muted);display:flex;align-items:center;gap:10px">
              <div style="width:32px;height:32px;border-radius:50%;background:var(--accent-bg);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;color:var(--accent);flex-shrink:0">
                {{ (op.name || op.id).slice(0,1).toUpperCase() }}
              </div>
              <div style="flex:1;min-width:0">
                <div style="font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  {{ op.name || 'Operator' }}
                </div>
                <div style="font-size:11px;color:var(--text-muted)">{{ op.id?.slice(0,8) }}</div>
              </div>
              <div style="font-size:10px;color:var(--green)">●</div>
            </div>
          </div>
        </div>

        <!-- Agent Claims -->
        <div class="card">
          <div class="card-header"><span class="card-title">Agent Claims</span></div>
          <div class="card-body" style="padding:0">
            <div v-if="!claims.length" class="empty-state" style="padding:20px">
              <div style="font-size:12px">No agents claimed</div>
            </div>
            <div v-for="c in claims" :key="c.agentId"
                 style="padding:8px 14px;border-bottom:1px solid var(--border-muted);font-size:12px">
              <div style="font-weight:500;color:var(--text-primary)">{{ agentName(c.agentId) }}</div>
              <div style="color:var(--text-muted)">claimed by {{ c.operator }}</div>
            </div>
          </div>
        </div>

        <!-- Broadcast -->
        <div class="card">
          <div class="card-header"><span class="card-title">Broadcast Message</span></div>
          <div class="card-body" style="display:flex;flex-direction:column;gap:8px">
            <input v-model="broadcastMsg" class="input" placeholder="Message to all operators…" @keyup.enter="sendBroadcast" />
            <button class="btn btn-primary" @click="sendBroadcast" :disabled="!broadcastMsg.trim() || broadcasting">
              <div v-if="broadcasting" class="loading-spinner" style="width:12px;height:12px" />
              <span v-else>Broadcast</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Live event feed -->
      <div class="card" style="min-height:600px;display:flex;flex-direction:column">
        <div class="card-header" style="justify-content:space-between">
          <span class="card-title">Live Event Feed</span>
          <div style="display:flex;gap:8px;align-items:center">
            <select v-model="filterType" class="input" style="width:140px;padding:4px 8px;font-size:12px">
              <option value="">All Events</option>
              <option value="agent_checkin">Agent Checkin</option>
              <option value="command_queued">Command Queued</option>
              <option value="command_result">Command Result</option>
              <option value="session_start">Session Start</option>
              <option value="note">Note</option>
              <option value="broadcast">Broadcast</option>
            </select>
            <button class="btn btn-ghost btn-sm" @click="events = []">Clear</button>
          </div>
        </div>
        <div class="event-feed" ref="feedEl">
          <div v-if="!filteredEvents.length" class="empty-state">
            <div style="font-size:13px">Waiting for events…</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Events appear here in real-time via SSE</div>
          </div>
          <div v-for="(ev, i) in filteredEvents" :key="i" class="event-entry" :class="ev.type">
            <div class="event-time">{{ fmtTs(ev.timestamp) }}</div>
            <div class="event-type-badge" :class="ev.type">{{ ev.type?.replace(/_/g,' ') }}</div>
            <div class="event-body">
              <span v-if="ev.agent_id" class="event-agent">
                {{ agentName(ev.agent_id) }}
              </span>
              <span v-if="ev.op_name" class="event-op">[{{ ev.op_name }}]</span>
              <span class="event-msg">{{ ev.message || ev.data }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Register modal -->
    <div v-if="showRegister" class="modal-overlay" @click.self="showRegister = false">
      <div class="modal">
        <div class="modal-header">Register Operator</div>
        <div class="modal-body" style="display:flex;flex-direction:column;gap:10px">
          <div>
            <label class="form-label">Operator Name</label>
            <input v-model="regName" class="input" placeholder="e.g. alice" @keyup.enter="register" />
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="showRegister = false">Cancel</button>
          <button class="btn btn-primary" @click="register" :disabled="!regName.trim()">Register</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useAgentStore } from '@/stores/agents'
import { teamApi } from '@/api'

const agentStore = useAgentStore()

interface TeamEvent {
  type:      string
  agent_id?: string
  op_name?:  string
  message?:  string
  data?:     string
  timestamp: string
}

interface Operator {
  id:   string
  name: string
}

interface Claim {
  agentId:  string
  operator: string
}

const operators   = ref<Operator[]>([])
const claims      = ref<Claim[]>([])
const events      = ref<TeamEvent[]>([])
const sseConnected = ref(false)
const filterType  = ref('')
const broadcastMsg = ref('')
const broadcasting = ref(false)
const showRegister = ref(false)
const regName      = ref('')
const feedEl       = ref<HTMLElement|null>(null)

let evtSource: EventSource | null = null

const filteredEvents = computed(() => {
  if (!filterType.value) return events.value
  return events.value.filter(e => e.type === filterType.value)
})

function agentName(id: string) {
  return agentStore.byId(id)?.hostname || id?.slice(0, 8) || '—'
}

function fmtTs(ts: string) {
  if (!ts) return ''
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
  } catch { return ts }
}

function connectSSE() {
  if (evtSource) { evtSource.close(); evtSource = null }
  const apiKey = localStorage.getItem('c2_api_key')
  const url = `/api/v1/team/events${apiKey ? `?key=${apiKey}` : ''}`
  evtSource = new EventSource(url)

  evtSource.onopen = () => { sseConnected.value = true }
  evtSource.onerror = () => {
    sseConnected.value = false
    setTimeout(connectSSE, 5000)
  }
  evtSource.onmessage = (e) => {
    try {
      const ev: TeamEvent = JSON.parse(e.data)
      events.value.unshift(ev)
      if (events.value.length > 500) events.value.pop()
      if (ev.type === 'agent_checkin' || ev.type === 'session_start') {
        fetchOperators()
      }
    } catch { /* ignore malformed */ }
  }
}

async function fetchOperators() {
  try {
    const r = await teamApi.operators()
    operators.value = r.data?.data?.operators || []
  } catch { /* ignore */ }
}

async function sendBroadcast() {
  if (!broadcastMsg.value.trim() || broadcasting.value) return
  broadcasting.value = true
  try {
    await teamApi.broadcast(broadcastMsg.value.trim())
    broadcastMsg.value = ''
  } catch { /* ignore */ }
  finally { broadcasting.value = false }
}

async function register() {
  if (!regName.value.trim()) return
  try {
    await teamApi.register(regName.value.trim())
    showRegister.value = false
    regName.value = ''
    fetchOperators()
  } catch { /* ignore */ }
}

watch(filteredEvents, () => {
  nextTick(() => {
    if (feedEl.value) feedEl.value.scrollTop = 0
  })
})

onMounted(() => {
  fetchOperators()
  connectSSE()
})

onUnmounted(() => {
  evtSource?.close()
})
</script>

<style scoped>
.form-label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
.sse-indicator {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: var(--r-full);
  font-size: 11px; font-weight: 500;
}
.sse-indicator.connected  { background: var(--green-bg);  color: var(--green); }
.sse-indicator.disconnected { background: var(--red-bg); color: var(--red); }

.event-feed {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
  min-height: 0;
  max-height: calc(100vh - 240px);
}
.event-entry {
  display: flex; align-items: baseline; gap: 10px;
  padding: 6px 16px;
  font-size: 12px;
  border-left: 2px solid transparent;
  transition: background var(--t-fast);
}
.event-entry:hover { background: var(--bg-hover); }
.event-entry.agent_checkin { border-left-color: var(--green); }
.event-entry.command_queued { border-left-color: var(--cyan); }
.event-entry.command_result { border-left-color: var(--accent); }
.event-entry.broadcast      { border-left-color: var(--purple); }
.event-entry.session_start  { border-left-color: var(--orange); }

.event-time { color: var(--text-muted); min-width: 72px; font-size: 10px; font-family: var(--font-mono); }
.event-type-badge {
  font-size: 9px; font-weight: 600; letter-spacing: .05em;
  text-transform: uppercase;
  padding: 1px 5px; border-radius: 3px;
  background: var(--bg-overlay); color: var(--text-muted);
  white-space: nowrap; flex-shrink: 0;
}
.event-type-badge.agent_checkin { background: var(--green-bg);  color: var(--green); }
.event-type-badge.command_queued{ background: var(--cyan-bg);   color: var(--cyan); }
.event-type-badge.command_result{ background: var(--accent-bg); color: var(--accent); }
.event-type-badge.broadcast     { background: var(--purple-bg); color: var(--purple); }
.event-type-badge.session_start { background: var(--orange-bg); color: var(--orange); }

.event-body { flex: 1; color: var(--text-secondary); }
.event-agent { color: var(--accent); margin-right: 4px; }
.event-op    { color: var(--cyan);   margin-right: 4px; font-family: var(--font-mono); font-size: 11px; }
.event-msg   { color: var(--text-secondary); }
</style>
