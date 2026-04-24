<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">Operations Overview</div>
      <div class="page-desc">Real-time agent and command status</div>
    </div>

    <!-- Stat Cards -->
    <div class="stat-grid">
      <div class="stat-card green">
        <div class="stat-label">Online Agents</div>
        <div class="stat-value" style="color:var(--green)">{{ agentStore.online.length }}</div>
        <div class="stat-sub">of {{ agentStore.agents.length }} total</div>
        <div class="stat-icon">🟢</div>
      </div>
      <div class="stat-card blue">
        <div class="stat-label">Total Agents</div>
        <div class="stat-value">{{ agentStore.agents.length }}</div>
        <div class="stat-sub">{{ agentStore.offline.length }} offline · {{ agentStore.dormant.length }} dormant</div>
        <div class="stat-icon">🖥</div>
      </div>
      <div class="stat-card cyan">
        <div class="stat-label">Commands Queued</div>
        <div class="stat-value" style="color:var(--cyan)">{{ queueStats?.pending ?? stats?.commands?.pending ?? 0 }}</div>
        <div class="stat-sub">{{ queueStats?.executing ?? stats?.commands?.executing ?? 0 }} executing</div>
        <div class="stat-icon">⚡</div>
      </div>
      <div class="stat-card purple">
        <div class="stat-label">Completed</div>
        <div class="stat-value" style="color:var(--purple)">{{ queueStats?.completed ?? stats?.commands?.completed ?? 0 }}</div>
        <div class="stat-sub">{{ queueStats?.failed ?? stats?.commands?.failed ?? 0 }} failed</div>
        <div class="stat-icon">✓</div>
      </div>
    </div>

    <!-- Main split -->
    <div style="display:grid;grid-template-columns:1fr 320px;gap:16px;align-items:start">

      <!-- Left column -->
      <div style="display:flex;flex-direction:column;gap:16px">

        <!-- Agent table -->
        <div class="card">
          <div class="card-header">
            <span class="card-title">Active Agents</span>
            <RouterLink to="/agents" class="btn btn-ghost btn-sm">View all →</RouterLink>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>OS</th>
                  <th>User</th>
                  <th>Privileges</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="agentStore.loading && !agentStore.agents.length" class="loading-row">
                  <td colspan="7"><div class="loading-spinner" style="margin:0 auto" /></td>
                </tr>
                <tr v-else-if="!agentStore.agents.length" class="loading-row">
                  <td colspan="7">No agents connected</td>
                </tr>
                <tr v-for="a in displayAgents" :key="a.id"
                    @click="$router.push('/agents/'+a.id)">
                  <td>
                    <div style="font-weight:500">{{ a.hostname }}</div>
                    <div class="td-mono td-muted" style="font-size:11px">{{ a.id.slice(0,8) }}</div>
                  </td>
                  <td class="td-muted">{{ osLabel(a.os) }}</td>
                  <td class="td-muted">{{ a.username }}</td>
                  <td>
                    <span v-if="a.privileges" :class="['priv-badge', a.privileges === 'admin' ? 'admin' : 'user']">
                      {{ a.privileges === 'admin' ? '★ Admin' : 'User' }}
                    </span>
                    <span v-else class="td-muted">—</span>
                  </td>
                  <td><StatusBadge :status="a.status" /></td>
                  <td class="td-muted" style="font-size:12px">{{ relTime(a.last_seen) }}</td>
                  <td>
                    <RouterLink :to="'/agents/'+a.id" class="btn btn-ghost btn-sm" @click.stop>
                      Console →
                    </RouterLink>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Server Health -->
        <div class="card">
          <div class="card-header" style="justify-content:space-between">
            <span class="card-title">Server Health</span>
            <span v-if="health" :class="['health-badge', health.status]">{{ health.status }}</span>
          </div>
          <div class="card-body">
            <div v-if="!health" style="color:var(--text-muted);font-size:13px">Loading…</div>
            <div v-else style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px">
              <div class="health-item">
                <div class="health-item-label">Version</div>
                <div class="health-item-value td-mono">{{ health.version }}</div>
              </div>
              <div class="health-item">
                <div class="health-item-label">Uptime</div>
                <div class="health-item-value">{{ health.uptime }}</div>
              </div>
              <div v-for="(state, comp) in health.components" :key="comp" class="health-item">
                <div class="health-item-label">{{ comp }}</div>
                <div :class="['health-item-value', state === 'healthy' ? 'text-green' : 'text-red']">
                  {{ state }}
                </div>
              </div>
            </div>
            <div v-if="health?.issues?.length" style="margin-top:10px">
              <div v-for="issue in health.issues" :key="issue"
                   style="font-size:12px;color:var(--orange);display:flex;align-items:center;gap:6px">
                ⚠ {{ issue }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Right column -->
      <div style="display:flex;flex-direction:column;gap:12px">

        <!-- Status breakdown -->
        <div class="card">
          <div class="card-header"><span class="card-title">Status Breakdown</span></div>
          <div class="card-body">
            <div v-for="row in statusRows" :key="row.label"
                 style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-muted)">
              <div style="display:flex;align-items:center;gap:8px;font-size:13px">
                <span class="badge-dot" :style="`background:${row.color};width:8px;height:8px;border-radius:50%;flex-shrink:0`" />
                {{ row.label }}
              </div>
              <span style="font-weight:600;font-variant-numeric:tabular-nums">{{ row.count }}</span>
            </div>
          </div>
        </div>

        <!-- Command queue -->
        <div class="card">
          <div class="card-header"><span class="card-title">Command Queue</span></div>
          <div class="card-body">
            <div v-for="row in queueRows" :key="row.label"
                 style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-muted)">
              <div style="font-size:13px;color:var(--text-secondary)">{{ row.label }}</div>
              <span :style="`font-weight:600;font-variant-numeric:tabular-nums;color:${row.color}`">{{ row.count }}</span>
            </div>
          </div>
        </div>

        <!-- Recent checkins -->
        <div class="card">
          <div class="card-header"><span class="card-title">Recent Checkins</span></div>
          <div class="card-body" style="padding:0">
            <div v-if="!recentAgents.length" class="empty-state" style="padding:20px">
              <div style="font-size:13px">No recent activity</div>
            </div>
            <div v-for="a in recentAgents" :key="a.id"
                 style="padding:9px 14px;border-bottom:1px solid var(--border-muted);display:flex;align-items:center;gap:10px;cursor:pointer"
                 @click="$router.push('/agents/'+a.id)">
              <div :style="`background:var(--status-${a.status});width:7px;height:7px;border-radius:50%;flex-shrink:0`" />
              <div style="flex:1;overflow:hidden">
                <div style="font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ a.hostname }}</div>
                <div style="font-size:11px;color:var(--text-muted)">{{ relTime(a.last_seen) }}</div>
              </div>
              <span v-if="a.privileges === 'admin'" style="font-size:10px;color:var(--orange)">★</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAgentStore } from '@/stores/agents'
import { serverApi, commandApi } from '@/api'
import type { HealthStatus } from '@/api'
import StatusBadge from '@/components/ui/StatusBadge.vue'

const agentStore = useAgentStore()
const stats      = computed(() => agentStore.stats)
const health     = ref<HealthStatus | null>(null)
const queueStats = ref<Record<string, number> | null>(null)

const displayAgents = computed(() =>
  [...agentStore.agents]
    .sort((a, b) => (b.status === 'online' ? 1 : 0) - (a.status === 'online' ? 1 : 0))
    .slice(0, 15)
)

const recentAgents = computed(() =>
  [...agentStore.agents]
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, 8)
)

const statusRows = computed(() => [
  { label: 'Online',  color: 'var(--green)',  count: agentStore.online.length },
  { label: 'Dormant', color: 'var(--orange)', count: agentStore.dormant.length },
  { label: 'Offline', color: 'var(--red)',    count: agentStore.offline.length },
])

const queueRows = computed(() => [
  { label: 'Pending',   color: 'var(--cyan)',   count: queueStats.value?.pending   ?? stats.value?.commands?.pending   ?? 0 },
  { label: 'Executing', color: 'var(--orange)', count: queueStats.value?.executing ?? stats.value?.commands?.executing ?? 0 },
  { label: 'Completed', color: 'var(--green)',  count: queueStats.value?.completed ?? stats.value?.commands?.completed ?? 0 },
  { label: 'Failed',    color: 'var(--red)',    count: queueStats.value?.failed    ?? stats.value?.commands?.failed    ?? 0 },
])

async function fetchHealth() {
  try {
    const r = await serverApi.health()
    health.value = r.data?.data ?? null
  } catch { /* ignore */ }
}

async function fetchQueueStats() {
  try {
    const r = await commandApi.stats()
    queueStats.value = r.data?.data as Record<string, number> ?? null
  } catch { /* ignore */ }
}

function osLabel(os: string) {
  if (!os) return '—'
  const l = os.toLowerCase()
  if (l.includes('windows')) return 'Windows'
  if (l.includes('linux'))   return 'Linux'
  if (l.includes('darwin'))  return 'macOS'
  return os.split(' ')[0]
}

function relTime(ts: string) {
  if (!ts) return '—'
  const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (sec < 5)     return 'just now'
  if (sec < 60)    return `${sec}s ago`
  if (sec < 3600)  return `${Math.floor(sec/60)}m ago`
  if (sec < 86400) return `${Math.floor(sec/3600)}h ago`
  return `${Math.floor(sec/86400)}d ago`
}

let timer: ReturnType<typeof setInterval>
onMounted(() => {
  fetchHealth()
  fetchQueueStats()
  timer = setInterval(() => { fetchHealth(); fetchQueueStats() }, 30_000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.priv-badge {
  font-size: 10px; font-weight: 600;
  padding: 2px 6px; border-radius: var(--r-full);
}
.priv-badge.admin { background: var(--orange-bg); color: var(--orange); }
.priv-badge.user  { background: var(--bg-overlay); color: var(--text-muted); }

.health-badge {
  font-size: 11px; font-weight: 600; padding: 2px 8px;
  border-radius: var(--r-full);
}
.health-badge.healthy   { background: var(--green-bg);  color: var(--green); }
.health-badge.degraded  { background: var(--orange-bg); color: var(--orange); }
.health-badge.unhealthy { background: var(--red-bg);    color: var(--red); }

.health-item { padding: 8px 10px; background: var(--bg-elevated); border-radius: var(--r-md); }
.health-item-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; margin-bottom: 2px; }
.health-item-value { font-size: 13px; font-weight: 500; color: var(--text-primary); }
.text-green { color: var(--green) !important; }
.text-red   { color: var(--red)   !important; }
</style>
