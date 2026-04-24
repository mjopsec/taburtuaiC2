<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">Server Logs</div>
        <div class="page-desc">Real-time server activity and event log</div>
      </div>
    </div>

    <!-- Controls -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-body" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input v-model="search" class="input" placeholder="Filter logs…"
               style="flex:1;min-width:180px;max-width:300px" />
        <div class="flex gap-2">
          <button v-for="lvl in levels" :key="lvl.value"
                  :class="['btn btn-sm', activeLevel === lvl.value ? 'btn-primary' : 'btn-ghost']"
                  @click="activeLevel = lvl.value">
            <span :style="`color:${lvl.color}`">{{ lvl.label }}</span>
          </button>
        </div>
        <button class="btn btn-ghost btn-sm" @click="clearLogs">Clear</button>
        <button class="btn btn-ghost btn-sm" :class="liveMode && 'btn-primary'" @click="toggleLive">
          {{ liveMode ? '⏸ Live' : '▶ Live' }}
        </button>
        <button class="btn btn-ghost btn-sm" @click="refresh" :disabled="loading">Refresh</button>
      </div>
    </div>

    <!-- Log viewer -->
    <div class="card">
      <div class="card-header" style="justify-content:space-between">
        <span class="card-title">Events</span>
        <span style="font-size:12px;color:var(--text-muted)">{{ filtered.length }} entries</span>
      </div>
      <div class="log-viewer" ref="logEl">
        <div v-if="loading && !logs.length" style="padding:24px;text-align:center">
          <div class="loading-spinner" style="margin:0 auto" />
        </div>
        <div v-else-if="!filtered.length" class="empty-state" style="padding:32px">
          <div>No log entries</div>
        </div>
        <div v-for="(entry, i) in filtered" :key="i" :class="['log-entry', entry.level]">
          <span class="log-ts">{{ fmtTs(entry.ts) }}</span>
          <span class="log-level-badge" :style="`color:${levelColor(entry.level)}`">
            {{ (entry.level || 'info').toUpperCase().padEnd(5) }}
          </span>
          <span class="log-msg">{{ entry.message }}</span>
          <span v-if="entry.agent_id" class="log-tag">
            {{ agentStore.byId(entry.agent_id)?.hostname || entry.agent_id.slice(0,8) }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useAgentStore } from '@/stores/agents'
import { serverApi } from '@/api'
import type { LogEntry } from '@/api/types'

const agentStore = useAgentStore()

const logs        = ref<LogEntry[]>([])
const loading     = ref(false)
const search      = ref('')
const activeLevel = ref('all')
const liveMode    = ref(true)
const logEl       = ref<HTMLElement|null>(null)

const levels = [
  { value: 'all',   label: 'All',   color: 'var(--text-secondary)' },
  { value: 'info',  label: 'Info',  color: 'var(--cyan)' },
  { value: 'warn',  label: 'Warn',  color: 'var(--orange)' },
  { value: 'error', label: 'Error', color: 'var(--red)' },
]

async function refresh() {
  loading.value = true
  try {
    const resp = await serverApi.logs({ limit: 500 })
    logs.value = resp.data?.data?.logs || []
    scrollBottom()
  } catch { /* ignore */ }
  finally { loading.value = false }
}

function clearLogs() { logs.value = [] }

function toggleLive() { liveMode.value = !liveMode.value }

function scrollBottom() {
  nextTick(() => {
    if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight
  })
}

const filtered = computed(() => {
  let list = logs.value
  if (activeLevel.value !== 'all') list = list.filter(e => e.level === activeLevel.value)
  if (search.value.trim()) {
    const q = search.value.toLowerCase()
    list = list.filter(e =>
      (e.message || '').toLowerCase().includes(q) ||
      (e.agent_id || '').toLowerCase().includes(q)
    )
  }
  return list
})

function levelColor(level: string) {
  switch (level) {
    case 'warn':  return 'var(--orange)'
    case 'error': return 'var(--red)'
    default:      return 'var(--cyan)'
  }
}

function fmtTs(ts: string) {
  if (!ts) return ''
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return ts }
}

watch(filtered, () => {
  if (liveMode.value) scrollBottom()
})

let timer: ReturnType<typeof setInterval>
onMounted(() => {
  refresh()
  timer = setInterval(() => { if (liveMode.value) refresh() }, 5_000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.log-viewer {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  background: var(--bg-deep);
  border-radius: 0 0 var(--radius) var(--radius);
  min-height: 400px;
  max-height: calc(100vh - 280px);
  overflow-y: auto;
  padding: 8px 0;
}
.log-entry {
  display: flex;
  gap: 10px;
  align-items: baseline;
  padding: 3px 16px;
  line-height: 1.5;
  border-left: 2px solid transparent;
}
.log-entry:hover { background: var(--bg-overlay); }
.log-entry.error { border-left-color: var(--red); }
.log-entry.warn  { border-left-color: var(--orange); }
.log-ts { color: var(--text-muted); min-width: 80px; font-size: 10px; }
.log-level-badge { font-size: 10px; min-width: 44px; }
.log-msg { color: var(--text-primary); flex: 1; word-break: break-all; }
.log-tag {
  color: var(--text-muted);
  font-size: 10px;
  background: var(--bg-overlay);
  padding: 1px 5px;
  border-radius: 3px;
  white-space: nowrap;
}
</style>
