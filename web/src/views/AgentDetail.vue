<template>
  <div class="page" style="max-width:100%">
    <!-- Header -->
    <div class="page-header" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:12px">
        <button class="btn btn-ghost btn-sm btn-icon" @click="$router.back()">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M7.78 12.53a.75.75 0 01-1.06 0L2.47 8.28a.75.75 0 010-1.06l4.25-4.25a.75.75 0 011.06 1.06L4.81 7h7.44a.75.75 0 010 1.5H4.81l2.97 2.97a.75.75 0 010 1.06z"/>
          </svg>
        </button>
        <div>
          <div class="page-title" style="display:flex;align-items:center;gap:10px">
            {{ agent?.hostname || 'Unknown' }}
            <StatusBadge v-if="agent" :status="agent.status" />
          </div>
          <div class="page-desc td-mono">{{ agentId }}</div>
        </div>
      </div>
    </div>

    <div v-if="!agent && !agentStore.loading" class="card" style="padding:48px;text-align:center">
      <div style="color:var(--text-muted);font-size:14px">Agent not found or has been removed.</div>
      <RouterLink to="/agents" class="btn btn-ghost btn-sm" style="margin-top:12px">← Back to Agents</RouterLink>
    </div>

    <div v-else style="display:grid;grid-template-columns:300px 1fr;gap:16px;align-items:start">

      <!-- Left: agent info -->
      <div style="display:flex;flex-direction:column;gap:12px">
        <!-- Info card -->
        <div class="card">
          <div class="card-header"><span class="card-title">Agent Info</span></div>
          <div class="card-body" style="padding:0">
            <table class="info-table">
              <tbody>
                <tr><td class="info-label">ID</td>
                    <td class="td-mono" style="font-size:11px;word-break:break-all">{{ agent?.id }}</td></tr>
                <tr><td class="info-label">Hostname</td><td>{{ agent?.hostname || '—' }}</td></tr>
                <tr><td class="info-label">User</td><td>{{ agent?.username || '—' }}</td></tr>
                <tr><td class="info-label">OS</td><td>{{ agent?.os || '—' }}</td></tr>
                <tr><td class="info-label">IP</td><td class="td-mono">{{ agent?.ip || '—' }}</td></tr>
                <tr><td class="info-label">Arch</td><td>{{ agent?.arch || '—' }}</td></tr>
                <tr><td class="info-label">PID</td><td class="td-mono">{{ agent?.pid || '—' }}</td></tr>
                <tr><td class="info-label">Interval</td><td>{{ agent?.check_in_interval ? agent.check_in_interval + 's' : '—' }}</td></tr>
                <tr><td class="info-label">Last Seen</td><td>{{ relTime(agent?.last_seen || '') }}</td></tr>
                <tr><td class="info-label">First Seen</td><td>{{ fmtDate(agent?.first_seen || '') }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Command stats -->
        <div class="card">
          <div class="card-header"><span class="card-title">Command Stats</span></div>
          <div class="card-body">
            <div v-for="row in cmdStats" :key="row.label"
                 style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border-muted);font-size:13px">
              <span style="color:var(--text-secondary)">{{ row.label }}</span>
              <span :style="`color:${row.color};font-weight:600`">{{ row.value }}</span>
            </div>
          </div>
        </div>

        <!-- Danger zone -->
        <div class="card">
          <div class="card-header"><span class="card-title" style="color:var(--red)">Danger Zone</span></div>
          <div class="card-body" style="display:flex;flex-direction:column;gap:8px">
            <button class="btn btn-ghost btn-sm" style="color:var(--orange);justify-content:flex-start"
                    @click="queueKill">
              ⚡ Queue Agent Kill
            </button>
            <button class="btn btn-ghost btn-sm" style="color:var(--red);justify-content:flex-start"
                    @click="confirmRemove = true">
              🗑 Remove from Server
            </button>
          </div>
        </div>
      </div>

      <!-- Right: console + history -->
      <div style="display:flex;flex-direction:column;gap:12px;min-width:0">

        <!-- Tabs -->
        <div class="tab-bar">
          <button v-for="tab in tabsWithBadge" :key="tab.id"
                  :class="['tab-btn', activeTab === tab.id && 'active']"
                  @click="activeTab = tab.id">
            {{ tab.label }}
            <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
          </button>
        </div>

        <!-- Console tab -->
        <template v-if="activeTab === 'console'">
          <!-- Terminal output -->
          <div class="card" style="flex:1">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Terminal</span>
              <div style="display:flex;gap:8px">
                <button class="btn btn-ghost btn-sm" @click="clearTerminal">Clear</button>
                <button class="btn btn-ghost btn-sm" :class="autoScroll && 'btn-primary'"
                        @click="autoScroll = !autoScroll">
                  Auto-scroll
                </button>
              </div>
            </div>
            <div class="terminal" ref="termEl" @scroll="onScroll">
              <div v-if="!termLines.length" style="color:var(--text-muted);font-style:italic">
                No output yet. Queue a command below.
              </div>
              <div v-for="(line, i) in termLines" :key="i" :class="['term-line', line.type]">
                <span class="term-ts">{{ line.ts }}</span>
                <span class="term-cmd" v-if="line.type === 'cmd'">▶ </span>
                <span class="term-out" v-else-if="line.type === 'out'">  </span>
                <span class="term-err" v-else-if="line.type === 'err'">✕ </span>
                <span class="term-info" v-else-if="line.type === 'info'">ℹ </span>
                <span class="term-content" v-html="highlight(line.text)" />
              </div>
            </div>
          </div>

          <!-- Command input -->
          <div class="card">
            <div class="card-header"><span class="card-title">Queue Command</span></div>
            <div class="card-body" style="display:flex;flex-direction:column;gap:12px">
              <!-- Op selector -->
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <select v-model="selectedOp" class="input" style="flex:1;min-width:180px">
                  <optgroup v-for="grp in opGroups" :key="grp.label" :label="grp.label">
                    <option v-for="op in grp.ops" :key="op.value" :value="op.value">{{ op.label }}</option>
                  </optgroup>
                </select>
                <input v-model="cmdArgs" class="input input-mono" style="flex:2;min-width:200px"
                       :placeholder="opPlaceholder"
                       @keyup.enter="queueCommand" />
              </div>
              <!-- Extra fields for complex ops -->
              <div v-if="needsPayload" style="display:flex;gap:8px">
                <textarea v-model="cmdPayload" class="input input-mono"
                          style="flex:1;min-height:80px;resize:vertical;font-size:12px"
                          placeholder='{"key": "value"} — JSON payload' />
              </div>
              <div style="display:flex;justify-content:flex-end;gap:8px">
                <button class="btn btn-ghost btn-sm" @click="cmdArgs='';cmdPayload=''">Clear</button>
                <button class="btn btn-primary" @click="queueCommand" :disabled="!selectedOp || queueing">
                  <div v-if="queueing" class="loading-spinner" style="width:12px;height:12px" />
                  <span v-else>Queue →</span>
                </button>
              </div>
            </div>
          </div>
        </template>

        <!-- History tab -->
        <template v-if="activeTab === 'history'">
          <div class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Command History</span>
              <button class="btn btn-ghost btn-sm" @click="fetchCommands">Refresh</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Op</th>
                    <th>Status</th>
                    <th>Queued</th>
                    <th>Duration</th>
                    <th style="width:60px"></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-if="loadingCmds" class="loading-row">
                    <td colspan="5"><div class="loading-spinner" style="margin:0 auto" /></td>
                  </tr>
                  <tr v-else-if="!agentCmds.length" class="loading-row">
                    <td colspan="5">No commands yet</td>
                  </tr>
                  <tr v-for="c in agentCmds" :key="c.id"
                      @click="selectCmd(c)" class="clickable"
                      :class="selectedCmdId === c.id && 'row-selected'">
                    <td class="td-mono" style="font-size:12px">{{ c.op }}</td>
                    <td><CmdStatusBadge :status="c.status" /></td>
                    <td class="td-muted" style="font-size:12px">{{ relTime(c.created_at) }}</td>
                    <td class="td-muted" style="font-size:12px">{{ duration(c) }}</td>
                    <td>
                      <button class="btn btn-ghost btn-sm btn-icon" @click.stop="showOutput(c)"
                              title="View output">
                        <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                          <path d="M0 2.75A1.75 1.75 0 011.75 1h12.5A1.75 1.75 0 0116 2.75v10.5A1.75 1.75 0 0114.25 15H1.75A1.75 1.75 0 010 13.25V2.75zm1.75-.25a.25.25 0 00-.25.25v10.5c0 .138.112.25.25.25h12.5a.25.25 0 00.25-.25V2.75a.25.25 0 00-.25-.25H1.75zm3.72 3.22a.75.75 0 010 1.06L4.31 8l1.16 1.22a.75.75 0 11-1.09 1.03l-1.75-1.84a.75.75 0 010-1.03l1.75-1.84a.75.75 0 011.06.03zm4.56 0a.75.75 0 011.06-.03l1.75 1.84a.75.75 0 010 1.03l-1.75 1.84a.75.75 0 11-1.09-1.03L11.69 8l-1.16-1.22a.75.75 0 01.03-1.06zm-1.78.28a.75.75 0 01.45.96l-1.5 4a.75.75 0 01-1.41-.52l1.5-4a.75.75 0 01.96-.44z"/>
                        </svg>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- Output panel -->
            <div v-if="selectedCmd" style="border-top:1px solid var(--border-muted);padding:12px 16px">
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;display:flex;justify-content:space-between">
                <span>Output — {{ selectedCmd.op }}</span>
                <button class="btn btn-ghost btn-sm" style="padding:0 6px;height:20px;font-size:10px"
                        @click="selectedCmd = null">✕</button>
              </div>
              <div class="terminal" style="min-height:80px;max-height:300px">
                <pre style="margin:0;white-space:pre-wrap;word-break:break-all">{{ selectedCmd.output || '(no output)' }}</pre>
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- Remove confirm -->
    <div v-if="confirmRemove" class="modal-overlay" @click.self="confirmRemove = false">
      <div class="modal">
        <div class="modal-header">Remove Agent</div>
        <div class="modal-body">
          <p style="font-size:13px;color:var(--text-secondary)">
            Remove <strong style="color:var(--text-primary)">{{ agent?.hostname }}</strong> from the server?
          </p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="confirmRemove = false">Cancel</button>
          <button class="btn btn-danger" @click="doRemove">Remove</button>
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
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAgentStore } from '@/stores/agents'
import { commandApi } from '@/api'
import type { Command } from '@/api/types'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import CmdStatusBadge from '@/components/ui/CmdStatusBadge.vue'

const route      = useRoute()
const router     = useRouter()
const agentStore = useAgentStore()

const agentId = computed(() => route.params.id as string)
const agent   = computed(() => agentStore.byId(agentId.value))

// Tabs
const activeTab = ref<'console'|'history'>('console')
const tabs: { id: 'console'|'history'; label: string; badge?: number }[] = [
  { id: 'console', label: 'Console' },
  { id: 'history', label: 'History' },
]
const tabsWithBadge = computed(() =>
  tabs.map(t => ({ ...t, badge: t.id === 'history' ? agentCmds.value.length || undefined : undefined }))
)

// Terminal
interface TermLine { type: 'cmd'|'out'|'err'|'info'; text: string; ts: string }
const termLines  = ref<TermLine[]>([])
const termEl     = ref<HTMLElement|null>(null)
const autoScroll = ref(true)

function addLine(type: TermLine['type'], text: string) {
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
  termLines.value.push({ type, text, ts })
  if (autoScroll.value) nextTick(() => {
    if (termEl.value) termEl.value.scrollTop = termEl.value.scrollHeight
  })
}

function clearTerminal() { termLines.value = [] }

function onScroll() {
  if (!termEl.value) return
  const { scrollTop, scrollHeight, clientHeight } = termEl.value
  autoScroll.value = scrollHeight - scrollTop - clientHeight < 32
}

function highlight(text: string) {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/("[\w-]+")\s*:/g, '<span style="color:var(--cyan)">$1</span>:')
    .replace(/\b(true|false|null)\b/g, '<span style="color:var(--purple)">$1</span>')
    .replace(/\b(\d+)\b/g, '<span style="color:var(--orange)">$1</span>')
}

// Command queueing
const selectedOp  = ref('shell')
const cmdArgs     = ref('')
const cmdPayload  = ref('')
const queueing    = ref(false)

const opGroups = [
  { label: 'Execution', ops: [
    { value: 'shell',        label: 'Shell Command' },
    { value: 'powershell',   label: 'PowerShell' },
    { value: 'ps_runspace',  label: 'PS Runspace' },
    { value: 'dotnet_exec',  label: '.NET Exec (BOF)' },
    { value: 'pe_load',      label: 'PE Load (in-memory)' },
  ]},
  { label: 'Recon', ops: [
    { value: 'screenshot',   label: 'Screenshot' },
    { value: 'keylog_start', label: 'Keylog Start' },
    { value: 'keylog_dump',  label: 'Keylog Dump' },
    { value: 'keylog_stop',  label: 'Keylog Stop' },
    { value: 'netscan',      label: 'Network Scan' },
  ]},
  { label: 'File Ops', ops: [
    { value: 'ls',           label: 'List Files' },
    { value: 'cd',           label: 'Change Dir' },
    { value: 'upload',       label: 'Upload File' },
    { value: 'download',     label: 'Download File' },
    { value: 'rm',           label: 'Delete File' },
    { value: 'mv',           label: 'Move/Rename' },
    { value: 'timestomp',    label: 'Timestomp' },
    { value: 'ads_write',    label: 'ADS Write' },
    { value: 'ads_exec',     label: 'ADS Exec' },
    { value: 'stego_extract',label: 'Stego Extract' },
  ]},
  { label: 'Privilege', ops: [
    { value: 'token_steal',  label: 'Token Steal' },
    { value: 'uac_bypass',   label: 'UAC Bypass' },
    { value: 'lsass_dump_dup', label: 'LSASS Dump (DupHandle)' },
    { value: 'lsass_dump_wer', label: 'LSASS Dump (WER)' },
  ]},
  { label: 'Evasion', ops: [
    { value: 'amsi_patch',   label: 'AMSI Patch' },
    { value: 'amsi_hwbp',    label: 'AMSI HWBP' },
    { value: 'etw_patch',    label: 'ETW Patch' },
    { value: 'etw_hwbp',     label: 'ETW HWBP' },
    { value: 'unhook',       label: 'Unhook NTDLL' },
    { value: 'opsec_timegate', label: 'OPSEC Timegate' },
  ]},
  { label: 'Lateral', ops: [
    { value: 'inject',       label: 'Process Inject' },
    { value: 'threadless_inject', label: 'Threadless Inject' },
    { value: 'ppid_spoof',   label: 'PPID Spoof' },
    { value: 'socks5_start', label: 'SOCKS5 Start' },
    { value: 'socks5_stop',  label: 'SOCKS5 Stop' },
  ]},
  { label: 'Persistence', ops: [
    { value: 'reg_set',      label: 'Registry Set' },
    { value: 'reg_get',      label: 'Registry Get' },
    { value: 'reg_delete',   label: 'Registry Delete' },
    { value: 'reg_query',    label: 'Registry Query' },
  ]},
  { label: 'Agent', ops: [
    { value: 'sleep',        label: 'Sleep (interval)' },
    { value: 'kill',         label: 'Kill Agent' },
  ]},
]

const opPlaceholder = computed(() => {
  const map: Record<string, string> = {
    shell:        'whoami /all',
    powershell:   'Get-Process | Select -First 5',
    ls:           'C:\\Windows\\System32',
    cd:           'C:\\Users',
    download:     'C:\\secret.txt',
    upload:       'C:\\dest.exe',
    rm:           'C:\\temp\\file.txt',
    mv:           'C:\\old.txt C:\\new.txt',
    inject:       '<pid> [shellcode-b64]',
    sleep:        '30 (seconds)',
    reg_set:      'HKLM\\SOFTWARE\\Key ValueName Data',
    netscan:      '192.168.1.0/24 --ports 22,80,443',
    timestomp:    'C:\\file.exe',
    ads_write:    'C:\\legit.txt:stream payload',
    ads_exec:     'C:\\legit.txt:payload.js',
    socks5_start: '127.0.0.1:1080',
  }
  return map[selectedOp.value] || 'Arguments…'
})

const needsPayload = computed(() =>
  ['dotnet_exec', 'pe_load', 'ps_runspace', 'threadless_inject'].includes(selectedOp.value)
)

async function queueCommand() {
  if (!selectedOp.value || queueing.value) return
  queueing.value = true

  const payload: Record<string, unknown> = { op: selectedOp.value }

  // Parse args string into appropriate fields
  const args = cmdArgs.value.trim()
  if (args) {
    if (selectedOp.value === 'shell' || selectedOp.value === 'powershell' || selectedOp.value === 'ps_runspace') {
      payload.cmd = args
    } else if (selectedOp.value === 'sleep') {
      payload.interval = parseInt(args) || 30
    } else if (selectedOp.value === 'inject' || selectedOp.value === 'threadless_inject') {
      const parts = args.split(' ')
      payload.pid = parseInt(parts[0])
      if (parts[1]) payload.shellcode = parts[1]
    } else if (selectedOp.value === 'socks5_start') {
      payload.socks5_addr = args
    } else if (['ls', 'cd', 'download', 'rm', 'upload', 'timestomp'].includes(selectedOp.value)) {
      payload.path = args
    } else if (selectedOp.value === 'mv') {
      const parts = args.split(' ')
      payload.src = parts[0]; payload.dst = parts[1]
    } else if (selectedOp.value === 'ppid_spoof') {
      payload.pid = parseInt(args)
    } else {
      payload.args = args
    }
  }

  if (cmdPayload.value.trim()) {
    try {
      const extra = JSON.parse(cmdPayload.value)
      Object.assign(payload, extra)
    } catch {
      addLine('err', 'Invalid JSON payload')
      queueing.value = false
      return
    }
  }

  addLine('cmd', `[${selectedOp.value}] ${args}`)

  try {
    const resp = await commandApi.queue(agentId.value, payload)
    const cmdId = resp.data?.data?.command_id
    addLine('info', `Queued → ${cmdId || 'ok'}`)
    cmdArgs.value = ''
    cmdPayload.value = ''
    // Poll for result
    if (cmdId) {
      pollResult(cmdId)
    }
    fetchCommands()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { error?: string } } }
    addLine('err', err?.response?.data?.error || 'Failed to queue command')
  } finally {
    queueing.value = false
  }
}

async function pollResult(cmdId: string) {
  const maxTries = 60
  let tries = 0
  const interval = setInterval(async () => {
    tries++
    try {
      const resp = await commandApi.get(cmdId)
      const cmd = resp.data?.data
      if (cmd?.status === 'completed' || cmd?.status === 'failed') {
        clearInterval(interval)
        const type = cmd.status === 'completed' ? 'out' : 'err'
        const text = cmd.output || `(${cmd.status})`
        text.split('\n').forEach((line: string) => addLine(type, line))
        fetchCommands()
      }
    } catch { /* ignore */ }
    if (tries >= maxTries) clearInterval(interval)
  }, 2000)
  pollers.value.push(interval)
}

async function queueKill() {
  addLine('cmd', '[kill] Queuing agent self-destruct…')
  try {
    const resp = await commandApi.queue(agentId.value, { op: 'kill' })
    addLine('info', `Kill queued → ${resp.data?.data?.command_id || 'ok'}`)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { error?: string } } }
    addLine('err', err?.response?.data?.error || 'Failed')
  }
}

// Command history
const agentCmds     = ref<Command[]>([])
const loadingCmds   = ref(false)
const selectedCmdId = ref<string|null>(null)
const selectedCmd   = ref<Command|null>(null)
const outputModal   = ref<Command|null>(null)
const pollers       = ref<ReturnType<typeof setInterval>[]>([])

async function fetchCommands() {
  loadingCmds.value = true
  try {
    const resp = await commandApi.list({ agent_id: agentId.value, limit: 50 })
    agentCmds.value = resp.data?.data?.commands || []
  } catch { /* ignore */ }
  finally { loadingCmds.value = false }
}

function selectCmd(c: Command) {
  selectedCmdId.value = c.id
  selectedCmd.value = c
}

function showOutput(c: Command) { outputModal.value = c }

async function copyOutput(c: Command) {
  await navigator.clipboard.writeText(c.output || '')
}

const confirmRemove = ref(false)
async function doRemove() {
  await agentStore.remove(agentId.value)
  router.push('/agents')
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

function fmtDate(ts: string) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })
}

function duration(c: Command) {
  if (!c.created_at || !c.updated_at) return '—'
  const ms = new Date(c.updated_at).getTime() - new Date(c.created_at).getTime()
  if (ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  return `${(ms/1000).toFixed(1)}s`
}

const cmdStats = computed(() => {
  const cmds = agentCmds.value
  return [
    { label: 'Total',     value: cmds.length,                                color: 'var(--text-primary)' },
    { label: 'Completed', value: cmds.filter(c => c.status === 'completed').length, color: 'var(--green)' },
    { label: 'Pending',   value: cmds.filter(c => c.status === 'pending').length,   color: 'var(--cyan)' },
    { label: 'Executing', value: cmds.filter(c => c.status === 'executing').length, color: 'var(--orange)' },
    { label: 'Failed',    value: cmds.filter(c => c.status === 'failed').length,    color: 'var(--red)' },
  ]
})

let refreshTimer: ReturnType<typeof setInterval>

onMounted(() => {
  fetchCommands()
  refreshTimer = setInterval(fetchCommands, 10_000)
})

onUnmounted(() => {
  clearInterval(refreshTimer)
  pollers.value.forEach(clearInterval)
})

watch(() => activeTab.value, (t) => {
  if (t === 'history') fetchCommands()
})
</script>

<style scoped>
.info-table { width: 100%; border-collapse: collapse; }
.info-table tr { border-bottom: 1px solid var(--border-muted); }
.info-table tr:last-child { border-bottom: none; }
.info-table td { padding: 7px 14px; font-size: 13px; }
.info-label { color: var(--text-muted); width: 90px; }
.terminal {
  background: var(--bg-deep);
  border-radius: var(--radius);
  padding: 12px 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  min-height: 220px;
  max-height: 420px;
  overflow-y: auto;
  line-height: 1.6;
}
.term-line { display: flex; gap: 6px; margin: 1px 0; }
.term-ts { color: var(--text-muted); min-width: 60px; font-size: 10px; padding-top: 1px; }
.term-line.cmd .term-content { color: var(--cyan); }
.term-line.out .term-content { color: var(--text-primary); }
.term-line.err .term-content { color: var(--red); }
.term-line.info .term-content { color: var(--text-muted); }
.term-cmd { color: var(--cyan); }
.term-err { color: var(--red); }
.term-info { color: var(--text-muted); }
.clickable { cursor: pointer; }
.row-selected { background: var(--bg-overlay) !important; }
.btn-danger { color: var(--red) !important; }
.btn-danger:hover { background: rgba(248,81,73,0.15) !important; }
</style>
