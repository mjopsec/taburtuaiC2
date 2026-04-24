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
        <div class="stat-value" style="color:var(--cyan)">{{ stats?.commands?.pending ?? 0 }}</div>
        <div class="stat-sub">{{ stats?.commands?.executing ?? 0 }} executing</div>
        <div class="stat-icon">⚡</div>
      </div>
      <div class="stat-card purple">
        <div class="stat-label">Completed</div>
        <div class="stat-value" style="color:var(--purple)">{{ stats?.commands?.completed ?? 0 }}</div>
        <div class="stat-sub">{{ stats?.commands?.failed ?? 0 }} failed</div>
        <div class="stat-icon">✓</div>
      </div>
    </div>

    <!-- Main split -->
    <div style="display:grid;grid-template-columns:1fr 340px;gap:20px;align-items:start">

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
                <th>Status</th>
                <th>Last Seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="agentStore.loading && !agentStore.agents.length" class="loading-row">
                <td colspan="6"><div class="loading-spinner" style="margin:0 auto" /></td>
              </tr>
              <tr v-else-if="!agentStore.agents.length" class="loading-row">
                <td colspan="6">No agents connected</td>
              </tr>
              <tr v-for="a in displayAgents" :key="a.id"
                  @click="$router.push('/agents/'+a.id)">
                <td>
                  <div style="font-weight:500">{{ a.hostname }}</div>
                  <div class="td-mono td-muted" style="font-size:11px">{{ a.id.slice(0,8) }}</div>
                </td>
                <td class="td-muted">{{ osLabel(a.os) }}</td>
                <td class="td-muted">{{ a.username }}</td>
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

      <!-- Right column -->
      <div style="display:flex;flex-direction:column;gap:16px">
        <!-- Quick stats -->
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

        <!-- Recent activity -->
        <div class="card">
          <div class="card-header"><span class="card-title">Recent Checkins</span></div>
          <div class="card-body" style="padding:0">
            <div v-if="!recentAgents.length" class="empty-state" style="padding:24px">
              <div>No recent activity</div>
            </div>
            <div v-for="a in recentAgents" :key="a.id"
                 style="padding:10px 16px;border-bottom:1px solid var(--border-muted);display:flex;align-items:center;gap:10px;cursor:pointer"
                 @click="$router.push('/agents/'+a.id)">
              <div :class="['badge-dot','flex-shrink:0']"
                   :style="`background:var(--status-${a.status});width:7px;height:7px;border-radius:50%`" />
              <div style="flex:1;overflow:hidden">
                <div style="font-size:13px;font-weight:500;truncate:1">{{ a.hostname }}</div>
                <div style="font-size:11px;color:var(--text-muted)">{{ relTime(a.last_seen) }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAgentStore } from '@/stores/agents'
import StatusBadge from '@/components/ui/StatusBadge.vue'

const agentStore = useAgentStore()
const stats = computed(() => agentStore.stats)

const displayAgents = computed(() =>
  [...agentStore.agents]
    .sort((a, b) => (b.status === 'online' ? 1 : 0) - (a.status === 'online' ? 1 : 0))
    .slice(0, 12)
)

const recentAgents = computed(() =>
  [...agentStore.agents]
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, 6)
)

const statusRows = computed(() => [
  { label: 'Online',   color: 'var(--green)',  count: agentStore.online.length },
  { label: 'Dormant',  color: 'var(--orange)', count: agentStore.dormant.length },
  { label: 'Offline',  color: 'var(--red)',    count: agentStore.offline.length },
])

function osLabel(os: string) {
  if (!os) return '—'
  if (os.toLowerCase().includes('windows')) return 'Windows'
  if (os.toLowerCase().includes('linux'))   return 'Linux'
  if (os.toLowerCase().includes('darwin'))  return 'macOS'
  return os.split(' ')[0]
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
</script>
