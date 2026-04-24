<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">Payload Stages</div>
        <div class="page-desc">Hosted payloads delivered via single-use encrypted tokens</div>
      </div>
      <button class="btn btn-primary" @click="showCreate = true">+ Upload Stage</button>
    </div>

    <!-- Stage list -->
    <div class="card">
      <div class="card-header" style="justify-content:space-between">
        <span class="card-title">Staged Payloads</span>
        <button class="btn btn-ghost btn-sm" @click="refresh" :disabled="loading">Refresh</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Token</th>
              <th>Format</th>
              <th>Arch</th>
              <th>OS</th>
              <th>Size</th>
              <th>Status</th>
              <th>Expires</th>
              <th>Description</th>
              <th style="width:100px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && !stages.length" class="loading-row">
              <td colspan="9"><div class="loading-spinner" style="margin:0 auto" /></td>
            </tr>
            <tr v-else-if="!stages.length" class="loading-row">
              <td colspan="9">No stages configured</td>
            </tr>
            <tr v-for="s in stages" :key="s.token" :class="s.used && 'row-used'">
              <td>
                <div class="td-mono" style="font-size:11px;color:var(--cyan)">{{ s.token?.slice(0,12) }}…</div>
              </td>
              <td><span class="type-badge" :class="s.format">{{ s.format }}</span></td>
              <td class="td-mono td-muted" style="font-size:12px">{{ s.arch }}</td>
              <td class="td-muted" style="font-size:12px">{{ s.os_target }}</td>
              <td class="td-muted" style="font-size:12px">{{ fmtSize(s.size) }}</td>
              <td>
                <span v-if="s.used" class="status-badge offline">
                  <span class="badge-dot" style="background:var(--text-muted)" />
                  Used
                </span>
                <span v-else-if="isExpired(s.expires_at)" class="status-badge offline">
                  <span class="badge-dot" style="background:var(--red)" />
                  Expired
                </span>
                <span v-else class="status-badge online">
                  <span class="badge-dot" style="background:var(--green)" />
                  Active
                </span>
              </td>
              <td class="td-muted" style="font-size:11px">
                {{ s.expires_at ? relTime(s.expires_at) : '∞' }}
              </td>
              <td class="td-muted" style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                {{ s.description || '—' }}
              </td>
              <td>
                <div style="display:flex;gap:4px">
                  <button class="btn btn-ghost btn-sm btn-icon" @click="copyUrl(s)" title="Copy URL" :disabled="s.used">
                    <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/>
                      <path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/>
                    </svg>
                  </button>
                  <button class="btn btn-ghost btn-sm btn-icon" @click="showDetail(s)" title="Details">
                    <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M0 8a8 8 0 1116 0A8 8 0 010 8zm8-6.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM6.5 7.75A.75.75 0 017.25 7h1a.75.75 0 01.75.75v2.75h.25a.75.75 0 010 1.5h-2a.75.75 0 010-1.5h.25v-2h-.25a.75.75 0 01-.75-.75zM8 6a1 1 0 110-2 1 1 0 010 2z"/>
                    </svg>
                  </button>
                  <button class="btn btn-ghost btn-sm btn-icon" @click="doDelete(s)" title="Delete" style="color:var(--red)">
                    <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M6.5 1.75a.25.25 0 01.25-.25h2.5a.25.25 0 01.25.25V3h-3V1.75zm4.5 0V3h2.25a.75.75 0 010 1.5H2.75a.75.75 0 010-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75zM4.496 6.675l.66 6.6a.25.25 0 00.249.225h5.19a.25.25 0 00.249-.225l.66-6.6a.75.75 0 011.49.149l-.66 6.6A1.748 1.748 0 0110.595 15h-5.19a1.75 1.75 0 01-1.74-1.576l-.66-6.6a.75.75 0 111.491-.149z"/>
                    </svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Upload modal -->
    <div v-if="showCreate" class="modal-overlay" @click.self="closeModal">
      <div class="modal" style="max-width:560px">
        <div class="modal-header">Upload Payload Stage</div>
        <div class="modal-body" style="display:flex;flex-direction:column;gap:14px">

          <!-- File picker -->
          <div>
            <label class="form-label">Payload File</label>
            <div class="file-drop" :class="dragOver && 'drag-over'"
                 @dragover.prevent="dragOver = true"
                 @dragleave="dragOver = false"
                 @drop.prevent="onDrop">
              <input ref="fileInput" type="file" style="display:none" @change="onFileChange" />
              <div v-if="!form.file" style="text-align:center;padding:20px 0;cursor:pointer" @click="fileInput?.click()">
                <div style="font-size:24px;margin-bottom:8px;opacity:.4">📁</div>
                <div style="font-size:13px;color:var(--text-secondary)">Drop file here or <span style="color:var(--accent);cursor:pointer">browse</span></div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Max 50MB</div>
              </div>
              <div v-else style="display:flex;align-items:center;gap:10px;padding:10px">
                <div style="font-size:20px">📄</div>
                <div style="flex:1;min-width:0">
                  <div style="font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ form.file.name }}</div>
                  <div style="font-size:11px;color:var(--text-muted)">{{ fmtSize(form.file.size) }}</div>
                </div>
                <button class="btn btn-ghost btn-sm btn-icon" @click="form.file = null">✕</button>
              </div>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
            <div>
              <label class="form-label">Format</label>
              <select v-model="form.format" class="input">
                <option value="exe">EXE</option>
                <option value="dll">DLL</option>
                <option value="shellcode">Shellcode</option>
                <option value="ps1">PowerShell</option>
                <option value="hta">HTA</option>
                <option value="js">JavaScript</option>
              </select>
            </div>
            <div>
              <label class="form-label">Arch</label>
              <select v-model="form.arch" class="input">
                <option value="amd64">x64</option>
                <option value="x86">x86</option>
                <option value="arm64">ARM64</option>
              </select>
            </div>
            <div>
              <label class="form-label">OS</label>
              <select v-model="form.os" class="input">
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <div>
              <label class="form-label">TTL (hours, 0 = unlimited)</label>
              <input v-model.number="form.ttl_hours" class="input" type="number" min="0" placeholder="0" />
            </div>
            <div>
              <label class="form-label">Description</label>
              <input v-model="form.description" class="input" placeholder="Optional notes" />
            </div>
          </div>

          <!-- Progress -->
          <div v-if="saving" style="text-align:center;padding:8px 0">
            <div class="loading-spinner" style="margin:0 auto;width:20px;height:20px" />
            <div style="font-size:12px;color:var(--text-muted);margin-top:8px">Encoding and uploading…</div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="closeModal" :disabled="saving">Cancel</button>
          <button class="btn btn-primary" @click="uploadStage" :disabled="!form.file || saving">
            Upload →
          </button>
        </div>
      </div>
    </div>

    <!-- Detail modal -->
    <div v-if="detailStage" class="modal-overlay" @click.self="detailStage = null">
      <div class="modal" style="max-width:520px">
        <div class="modal-header">Stage Details</div>
        <div class="modal-body">
          <table class="info-table" style="width:100%">
            <tbody>
              <tr><td class="info-label">Token</td>
                  <td class="td-mono" style="font-size:11px;word-break:break-all;color:var(--cyan)">{{ detailStage.token }}</td></tr>
              <tr><td class="info-label">Format</td><td>{{ detailStage.format }}</td></tr>
              <tr><td class="info-label">Arch</td><td>{{ detailStage.arch }}</td></tr>
              <tr><td class="info-label">OS</td><td>{{ detailStage.os_target }}</td></tr>
              <tr><td class="info-label">Size</td><td>{{ fmtSize(detailStage.size) }}</td></tr>
              <tr><td class="info-label">Created</td><td>{{ fmtDate(detailStage.created_at) }}</td></tr>
              <tr><td class="info-label">Expires</td><td>{{ detailStage.expires_at ? fmtDate(detailStage.expires_at) : 'Never' }}</td></tr>
              <tr><td class="info-label">Used</td><td>{{ detailStage.used ? '✓ Yes' : 'No' }}</td></tr>
              <tr v-if="detailStage.used_at"><td class="info-label">Used At</td><td>{{ fmtDate(detailStage.used_at) }}</td></tr>
              <tr v-if="detailStage.used_by_ip"><td class="info-label">Used By</td><td class="td-mono">{{ detailStage.used_by_ip }}</td></tr>
              <tr><td class="info-label">Description</td><td>{{ detailStage.description || '—' }}</td></tr>
              <tr><td class="info-label">URL</td>
                  <td>
                    <div style="display:flex;align-items:center;gap:6px">
                      <code class="td-mono" style="font-size:10px;color:var(--cyan);word-break:break-all">{{ stageUrl(detailStage) }}</code>
                      <button class="btn btn-ghost btn-sm btn-icon" @click="copyUrl(detailStage)">📋</button>
                    </div>
                  </td></tr>
            </tbody>
          </table>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="detailStage = null">Close</button>
          <button class="btn btn-danger" @click="doDelete(detailStage); detailStage = null">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { stageApi } from '@/api'
import type { Stage } from '@/api/types'

const stages     = ref<Stage[]>([])
const loading    = ref(false)
const saving     = ref(false)
const showCreate = ref(false)
const detailStage = ref<Stage|null>(null)
const dragOver   = ref(false)
const fileInput  = ref<HTMLInputElement|null>(null)

const form = ref({
  file:        null as File | null,
  format:      'exe',
  arch:        'amd64',
  os:          'windows',
  ttl_hours:   0,
  description: '',
})

async function refresh() {
  loading.value = true
  try {
    const r = await stageApi.list()
    stages.value = r.data?.data?.stages || []
  } catch { /* ignore */ }
  finally { loading.value = false }
}

function stageUrl(s: Stage) {
  return `${window.location.origin}/stage/${s.token}`
}

async function copyUrl(s: Stage) {
  await navigator.clipboard.writeText(stageUrl(s))
}

function showDetail(s: Stage) { detailStage.value = s }

async function doDelete(s: Stage) {
  if (!confirm(`Delete stage ${s.token?.slice(0,8)}…?`)) return
  try { await stageApi.delete(s.token); await refresh() } catch { /* ignore */ }
}

function onDrop(e: DragEvent) {
  dragOver.value = false
  const f = e.dataTransfer?.files[0]
  if (f) form.value.file = f
}

function onFileChange(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  if (f) form.value.file = f
}

async function uploadStage() {
  if (!form.value.file || saving.value) return
  saving.value = true
  try {
    const buf = await form.value.file.arrayBuffer()
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)))
    await stageApi.create({
      payload:     b64,
      format:      form.value.format,
      arch:        form.value.arch,
      os:          form.value.os,
      description: form.value.description,
      ttl_hours:   form.value.ttl_hours,
    })
    closeModal()
    await refresh()
  } catch { /* ignore */ }
  finally { saving.value = false }
}

function closeModal() {
  showCreate.value = false
  form.value = { file: null, format: 'exe', arch: 'amd64', os: 'windows', ttl_hours: 0, description: '' }
}

function fmtSize(bytes?: number) {
  if (!bytes) return '—'
  if (bytes < 1024)       return `${bytes} B`
  if (bytes < 1048576)    return `${(bytes/1024).toFixed(1)} KB`
  return `${(bytes/1048576).toFixed(1)} MB`
}

function isExpired(ts?: string) {
  if (!ts) return false
  return new Date(ts).getTime() < Date.now()
}

function relTime(ts: string) {
  if (!ts) return '—'
  const sec = Math.floor((new Date(ts).getTime() - Date.now()) / 1000)
  if (sec < 0) return 'expired'
  if (sec < 3600)  return `in ${Math.floor(sec/60)}m`
  if (sec < 86400) return `in ${Math.floor(sec/3600)}h`
  return `in ${Math.floor(sec/86400)}d`
}

function fmtDate(ts: string) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })
}

onMounted(refresh)
</script>

<style scoped>
.form-label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
.type-badge {
  padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-family: var(--font-mono);
  background: var(--bg-overlay); color: var(--text-secondary);
}
.type-badge.exe, .type-badge.dll { color: var(--orange); }
.type-badge.shellcode { color: var(--red); }
.type-badge.ps1 { color: var(--cyan); }
.row-used { opacity: .5; }
.info-table { border-collapse: collapse; }
.info-table tr { border-bottom: 1px solid var(--border-muted); }
.info-table tr:last-child { border-bottom: none; }
.info-table td { padding: 7px 12px; font-size: 13px; }
.info-label { color: var(--text-muted); width: 90px; }
.file-drop {
  border: 1px dashed var(--border);
  border-radius: var(--r-md);
  background: var(--bg-base);
  transition: border-color var(--t-fast), background var(--t-fast);
  min-height: 80px;
}
.file-drop.drag-over {
  border-color: var(--accent);
  background: var(--accent-bg);
}
</style>
