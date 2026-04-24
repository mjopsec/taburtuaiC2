<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">Agents</div>
        <div class="page-desc">All registered agents and their current status</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-body" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <input v-model="search" class="input" placeholder="Search hostname, user, IP…"
               style="flex:1;min-width:200px;max-width:320px" />
        <div class="flex gap-2" style="flex-wrap:wrap">
          <button v-for="f in statusFilters" :key="f.value"
                  :class="['btn btn-sm', activeFilter === f.value ? 'btn-primary' : 'btn-ghost']"
                  @click="activeFilter = f.value">
            {{ f.label }}
            <span v-if="f.count !== undefined"
                  style="margin-left:4px;padding:0 5px;border-radius:10px;font-size:11px;background:var(--bg-overlay)">
              {{ f.count }}
            </span>
          </button>
        </div>
        <button class="btn btn-ghost btn-sm btn-icon" @click="refresh()" :disabled="agentStore.loading">
          <div v-if="agentStore.loading" class="loading-spinner" style="width:13px;height:13px" />
          <svg v-else width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
            <path d="M1.705 8.005a.75.75 0 01.834.656 5.5 5.5 0 009.592 2.97l-1.204-1.204a.25.25 0 01.177-.427h3.646a.25.25 0 01.25.25v3.646a.25.25 0 01-.427.177l-1.38-1.38A7.002 7.002 0 011.05 8.84a.75.75 0 01.656-.834zM8 2.5a5.487 5.487 0 00-4.131 1.869l1.204 1.204A.25.25 0 014.896 6H1.25A.25.25 0 011 5.75V2.104a.25.25 0 01.427-.177l1.38 1.38A7.002 7.002 0 0114.95 7.16a.75.75 0 11-1.49.178A5.5 5.5 0 008 2.5z"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- Agent table -->
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th @click="sort('hostname')" class="sortable">
                Agent <span class="sort-icon">{{ sortIcon('hostname') }}</span>
              </th>
              <th @click="sort('os')" class="sortable">
                OS <span class="sort-icon">{{ sortIcon('os') }}</span>
              </th>
              <th>User</th>
              <th>IP</th>
              <th @click="sort('status')" class="sortable">
                Status <span class="sort-icon">{{ sortIcon('status') }}</span>
              </th>
              <th @click="sort('last_seen')" class="sortable">
                Last Seen <span class="sort-icon">{{ sortIcon('last_seen') }}</span>
              </th>
              <th @click="sort('check_in_interval')" class="sortable">
                Interval <span class="sort-icon">{{ sortIcon('check_in_interval') }}</span>
              </th>
              <th style="width:120px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="agentStore.loading && !agentStore.agents.length" class="loading-row">
              <td colspan="8"><div class="loading-spinner" style="margin:0 auto" /></td>
            </tr>
            <tr v-else-if="!filtered.length" class="loading-row">
              <td colspan="8">No agents match your filter</td>
            </tr>
            <tr v-for="a in sorted" :key="a.id" @click="$router.push('/agents/'+a.id)" class="clickable">
              <td>
                <div style="font-weight:500">{{ a.hostname }}</div>
                <div class="td-mono td-muted" style="font-size:11px">{{ a.id.slice(0,8) }}</div>
              </td>
              <td class="td-muted">
                <div style="display:flex;align-items:center;gap:6px">
                  <span class="os-icon">{{ osIcon(a.os) }}</span>
                  {{ osLabel(a.os) }}
                </div>
              </td>
              <td class="td-muted">{{ a.username || '—' }}</td>
              <td class="td-mono td-muted" style="font-size:12px">{{ a.ip || '—' }}</td>
              <td><StatusBadge :status="a.status" /></td>
              <td class="td-muted" style="font-size:12px">{{ relTime(a.last_seen) }}</td>
              <td class="td-muted" style="font-size:12px">{{ a.check_in_interval ? a.check_in_interval + 's' : '—' }}</td>
              <td>
                <div style="display:flex;gap:6px">
                  <RouterLink :to="'/agents/'+a.id" class="btn btn-ghost btn-sm" @click.stop>
                    Console →
                  </RouterLink>
                  <button class="btn btn-ghost btn-sm btn-danger" @click.stop="confirmRemove(a)"
                          title="Remove agent">✕</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Remove confirm modal -->
    <div v-if="removeTarget" class="modal-overlay" @click.self="removeTarget = null">
      <div class="modal">
        <div class="modal-header">Remove Agent</div>
        <div class="modal-body">
          <p style="font-size:13px;color:var(--text-secondary)">
            Remove <strong style="color:var(--text-primary)">{{ removeTarget.hostname }}</strong>
            (<code>{{ removeTarget.id.slice(0,8) }}</code>) from the server?
            The agent will re-register on next checkin.
          </p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="removeTarget = null">Cancel</button>
          <button class="btn btn-danger" @click="doRemove">Remove</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useAgentStore } from '@/stores/agents'
import type { Agent } from '@/api/types'
import StatusBadge from '@/components/ui/StatusBadge.vue'

const agentStore = useAgentStore()

const search      = ref('')
type FilterVal = 'all'|'online'|'dormant'|'offline'
const activeFilter = ref<FilterVal>('all')
const sortKey     = ref<keyof Agent>('status')
const sortDir     = ref<1|-1>(-1)
const removeTarget = ref<Agent|null>(null)

const statusFilters = computed(() => [
  { value: 'all'     as FilterVal, label: 'All',     count: agentStore.agents.length },
  { value: 'online'  as FilterVal, label: 'Online',  count: agentStore.online.length },
  { value: 'dormant' as FilterVal, label: 'Dormant', count: agentStore.dormant.length },
  { value: 'offline' as FilterVal, label: 'Offline', count: agentStore.offline.length },
])

const filtered = computed(() => {
  let list = agentStore.agents
  if (activeFilter.value !== 'all') list = list.filter(a => a.status === activeFilter.value)
  if (search.value.trim()) {
    const q = search.value.toLowerCase()
    list = list.filter(a =>
      a.hostname.toLowerCase().includes(q) ||
      (a.username || '').toLowerCase().includes(q) ||
      (a.ip || '').includes(q) ||
      a.id.toLowerCase().includes(q)
    )
  }
  return list
})

const sorted = computed(() => {
  return [...filtered.value].sort((a, b) => {
    const av = a[sortKey.value] ?? ''
    const bv = b[sortKey.value] ?? ''
    if (sortKey.value === 'last_seen') {
      return sortDir.value * (new Date(bv as string).getTime() - new Date(av as string).getTime())
    }
    return sortDir.value * String(av).localeCompare(String(bv))
  })
})

function sort(key: keyof Agent) {
  if (sortKey.value === key) sortDir.value = sortDir.value === 1 ? -1 : 1
  else { sortKey.value = key; sortDir.value = 1 }
}

function sortIcon(key: keyof Agent) {
  if (sortKey.value !== key) return '↕'
  return sortDir.value === 1 ? '↑' : '↓'
}

function osLabel(os: string) {
  if (!os) return '—'
  if (os.toLowerCase().includes('windows')) return 'Windows'
  if (os.toLowerCase().includes('linux'))   return 'Linux'
  if (os.toLowerCase().includes('darwin'))  return 'macOS'
  return os.split(' ')[0]
}

function osIcon(os: string) {
  if (!os) return '💻'
  if (os.toLowerCase().includes('windows')) return '🪟'
  if (os.toLowerCase().includes('linux'))   return '🐧'
  if (os.toLowerCase().includes('darwin'))  return '🍎'
  return '💻'
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

function confirmRemove(a: Agent) { removeTarget.value = a }

async function doRemove() {
  if (!removeTarget.value) return
  await agentStore.remove(removeTarget.value.id)
  removeTarget.value = null
}

async function refresh() {
  await agentStore.fetch()
}
</script>

<style scoped>
.sortable { cursor: pointer; user-select: none; }
.sortable:hover { background: var(--bg-overlay); }
.sort-icon { color: var(--text-muted); font-size: 11px; margin-left: 2px; }
.os-icon { font-size: 14px; }
.btn-danger { color: var(--red) !important; }
.btn-danger:hover { background: rgba(248,81,73,0.15) !important; }
.clickable { cursor: pointer; }
</style>
