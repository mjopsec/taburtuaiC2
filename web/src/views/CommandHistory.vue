<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">Command History</div>
        <div class="page-desc">All queued and executed commands across agents</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-body" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input v-model="search" class="input" placeholder="Search op, agent, output…"
               style="flex:1;min-width:180px;max-width:280px" />
        <select v-model="filterStatus" class="input" style="width:140px">
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="executing">Executing</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
        <select v-model="filterAgent" class="input" style="width:180px">
          <option value="">All Agents</option>
          <option v-for="a in agentStore.agents" :key="a.id" :value="a.id">
            {{ a.hostname }}
          </option>
        </select>
        <button class="btn btn-ghost btn-sm" @click="refresh" :disabled="loading">
          <div v-if="loading" class="loading-spinner" style="width:12px;height:12px" />
          <span v-else>Refresh</span>
        </button>
      </div>
    </div>

    <!-- Table -->
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Command ID</th>
              <th>Op</th>
              <th>Agent</th>
              <th>Status</th>
              <th>Queued</th>
              <th>Duration</th>
              <th style="width:50px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && !commands.length" class="loading-row">
              <td colspan="7"><div class="loading-spinner" style="margin:0 auto" /></td>
            </tr>
            <tr v-else-if="!filtered.length" class="loading-row">
              <td colspan="7">No commands match your filter</td>
            </tr>
            <tr v-for="c in filtered" :key="c.id" class="clickable" @click="selectCmd(c)"
                :class="selectedCmd?.id === c.id && 'row-selected'">
              <td class="td-mono td-muted" style="font-size:11px">{{ c.id.slice(0,12) }}</td>
              <td class="td-mono" style="font-size:12px;color:var(--cyan)">{{ c.op }}</td>
              <td class="td-muted" style="font-size:12px">
                <RouterLink :to="'/agents/'+c.agent_id" class="link" @click.stop>
                  {{ agentName(c.agent_id) }}
                </RouterLink>
              </td>
              <td><CmdStatusBadge :status="c.status" /></td>
              <td class="td-muted" style="font-size:12px">{{ relTime(c.created_at) }}</td>
              <td class="td-muted" style="font-size:12px">{{ duration(c) }}</td>
              <td>
                <button class="btn btn-ghost btn-sm btn-icon" @click.stop="outputModal = c" title="View output">
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M0 2.75A1.75 1.75 0 011.75 1h12.5A1.75 1.75 0 0116 2.75v10.5A1.75 1.75 0 0114.25 15H1.75A1.75 1.75 0 010 13.25V2.75zm1.75-.25a.25.25 0 00-.25.25v10.5c0 .138.112.25.25.25h12.5a.25.25 0 00.25-.25V2.75a.25.25 0 00-.25-.25H1.75zm3.72 3.22a.75.75 0 010 1.06L4.31 8l1.16 1.22a.75.75 0 11-1.09 1.03l-1.75-1.84a.75.75 0 010-1.03l1.75-1.84a.75.75 0 011.06.03zm4.56 0a.75.75 0 011.06-.03l1.75 1.84a.75.75 0 010 1.03l-1.75 1.84a.75.75 0 11-1.09-1.03L11.69 8l-1.16-1.22a.75.75 0 01.03-1.06zm-1.78.28a.75.75 0 01.45.96l-1.5 4a.75.75 0 01-1.41-.52l1.5-4a.75.75 0 01.96-.44z"/>
                  </svg>
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Inline output -->
      <div v-if="selectedCmd" style="border-top:1px solid var(--border-muted);padding:14px 16px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span style="font-size:12px;color:var(--text-muted)">
            Output — <code style="color:var(--cyan)">{{ selectedCmd.op }}</code>
            · {{ agentName(selectedCmd.agent_id) }}
          </span>
          <div style="display:flex;gap:8px">
            <button class="btn btn-ghost btn-sm" @click="copyOutput(selectedCmd)">Copy</button>
            <button class="btn btn-ghost btn-sm btn-icon" @click="selectedCmd = null">✕</button>
          </div>
        </div>
        <div class="terminal" style="max-height:280px">
          <pre style="margin:0;white-space:pre-wrap;word-break:break-all">{{ selectedCmd.output || '(no output)' }}</pre>
        </div>
      </div>
    </div>

    <!-- Output modal -->
    <div v-if="outputModal" class="modal-overlay" @click.self="outputModal = null">
      <div class="modal" style="max-width:720px;width:90vw">
        <div class="modal-header">
          Output — <code style="font-size:13px">{{ outputModal.op }}</code>
          <span style="margin-left:8px"><CmdStatusBadge :status="outputModal.status" /></span>
        </div>
        <div class="modal-body" style="padding:0">
          <div class="terminal" style="max-height:60vh;border-radius:0">
            <pre style="margin:0;white-space:pre-wrap;word-break:break-all">{{ outputModal.output || '(no output)' }}</pre>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="outputModal = null">Close</button>
          <button class="btn btn-ghost btn-sm" @click="copyOutput(outputModal)">Copy</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAgentStore } from '@/stores/agents'
import { commandApi } from '@/api'
import type { Command } from '@/api/types'
import CmdStatusBadge from '@/components/ui/CmdStatusBadge.vue'

const agentStore = useAgentStore()

const commands     = ref<Command[]>([])
const loading      = ref(false)
const search       = ref('')
const filterStatus = ref('')
const filterAgent  = ref('')
const selectedCmd  = ref<Command|null>(null)
const outputModal  = ref<Command|null>(null)

async function refresh() {
  loading.value = true
  try {
    const resp = await commandApi.list({ limit: 200 })
    commands.value = resp.data?.data?.commands || []
  } catch { /* ignore */ }
  finally { loading.value = false }
}

const filtered = computed(() => {
  let list = commands.value
  if (filterStatus.value) list = list.filter(c => c.status === filterStatus.value)
  if (filterAgent.value)  list = list.filter(c => c.agent_id === filterAgent.value)
  if (search.value.trim()) {
    const q = search.value.toLowerCase()
    list = list.filter(c =>
      c.op.toLowerCase().includes(q) ||
      c.id.toLowerCase().includes(q) ||
      (c.output || '').toLowerCase().includes(q) ||
      agentName(c.agent_id).toLowerCase().includes(q)
    )
  }
  return list
})

function agentName(id: string) {
  return agentStore.byId(id)?.hostname || id.slice(0, 8)
}

function selectCmd(c: Command) {
  selectedCmd.value = selectedCmd.value?.id === c.id ? null : c
}

async function copyOutput(c: Command) {
  await navigator.clipboard.writeText(c.output || '')
}

function relTime(ts: string) {
  if (!ts) return '—'
  const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (sec < 5)    return 'just now'
  if (sec < 60)   return `${sec}s ago`
  if (sec < 3600) return `${Math.floor(sec/60)}m ago`
  if (sec < 86400)return `${Math.floor(sec/3600)}h ago`
  return `${Math.floor(sec/86400)}d ago`
}

function duration(c: Command) {
  if (!c.created_at || !c.updated_at) return '—'
  const ms = new Date(c.updated_at).getTime() - new Date(c.created_at).getTime()
  if (ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  return `${(ms/1000).toFixed(1)}s`
}

let timer: ReturnType<typeof setInterval>
onMounted(() => { refresh(); timer = setInterval(refresh, 15_000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.terminal {
  background: var(--bg-deep);
  border-radius: var(--radius);
  padding: 12px 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  overflow-y: auto;
}
.clickable { cursor: pointer; }
.row-selected { background: var(--bg-overlay) !important; }
.link { color: var(--text-secondary); text-decoration: none; }
.link:hover { color: var(--text-primary); text-decoration: underline; }
</style>
