<template>
  <div class="page">
    <div class="page-header">
      <div>
        <div class="page-title">Payload Stages</div>
        <div class="page-desc">Hosted payloads and stager configuration</div>
      </div>
      <button class="btn btn-primary" @click="showCreate = true">+ New Stage</button>
    </div>

    <!-- Stage list -->
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>URL</th>
              <th>Downloads</th>
              <th>Created</th>
              <th style="width:80px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && !stages.length" class="loading-row">
              <td colspan="6"><div class="loading-spinner" style="margin:0 auto" /></td>
            </tr>
            <tr v-else-if="!stages.length" class="loading-row">
              <td colspan="6">No stages configured</td>
            </tr>
            <tr v-for="s in stages" :key="s.id">
              <td style="font-weight:500">{{ s.name }}</td>
              <td>
                <span class="type-badge" :class="s.type">{{ s.type }}</span>
              </td>
              <td>
                <div style="display:flex;align-items:center;gap:8px">
                  <code class="td-mono" style="font-size:11px;color:var(--cyan)">{{ stageUrl(s) }}</code>
                  <button class="btn btn-ghost btn-sm btn-icon" @click="copyUrl(s)" title="Copy URL">
                    <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"/>
                      <path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"/>
                    </svg>
                  </button>
                </div>
              </td>
              <td class="td-muted">{{ s.downloads ?? 0 }}</td>
              <td class="td-muted" style="font-size:12px">{{ relTime(s.created_at) }}</td>
              <td>
                <div style="display:flex;gap:4px">
                  <button class="btn btn-ghost btn-sm btn-icon" @click="editStage(s)" title="Edit">
                    <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M11.013 1.427a1.75 1.75 0 012.474 0l1.086 1.086a1.75 1.75 0 010 2.474l-8.61 8.61c-.21.21-.47.364-.756.445l-3.251.93a.75.75 0 01-.927-.928l.929-3.25c.081-.286.235-.547.445-.758l8.61-8.609zm1.414 1.06a.25.25 0 00-.354 0L10.811 3.75l1.439 1.44 1.263-1.263a.25.25 0 000-.354l-1.086-1.086zM11.189 6.25L9.75 4.81l-6.286 6.287a.25.25 0 00-.064.108l-.558 1.953 1.953-.558a.249.249 0 00.108-.064l6.286-6.286z"/>
                    </svg>
                  </button>
                  <button class="btn btn-ghost btn-sm btn-icon" @click="deleteStage(s)" title="Delete" style="color:var(--red)">
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

    <!-- Create/Edit modal -->
    <div v-if="showCreate || editTarget" class="modal-overlay" @click.self="closeModal">
      <div class="modal" style="max-width:520px">
        <div class="modal-header">{{ editTarget ? 'Edit Stage' : 'New Stage' }}</div>
        <div class="modal-body" style="display:flex;flex-direction:column;gap:12px">
          <div>
            <label class="form-label">Name</label>
            <input v-model="form.name" class="input" placeholder="e.g. win-agent-x64" />
          </div>
          <div>
            <label class="form-label">Type</label>
            <select v-model="form.type" class="input">
              <option value="exe">Executable (.exe)</option>
              <option value="dll">DLL (.dll)</option>
              <option value="ps1">PowerShell (.ps1)</option>
              <option value="raw">Raw shellcode</option>
              <option value="hta">HTA</option>
              <option value="js">JavaScript</option>
            </select>
          </div>
          <div>
            <label class="form-label">Description</label>
            <input v-model="form.description" class="input" placeholder="Optional notes" />
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="closeModal">Cancel</button>
          <button class="btn btn-primary" @click="saveStage" :disabled="!form.name || saving">
            <div v-if="saving" class="loading-spinner" style="width:12px;height:12px" />
            <span v-else>{{ editTarget ? 'Save' : 'Create' }}</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { stageApi } from '@/api'
import type { Stage } from '@/api/types'

const stages   = ref<Stage[]>([])
const loading  = ref(false)
const saving   = ref(false)
const showCreate = ref(false)
const editTarget = ref<Stage|null>(null)

const form = ref({ name: '', type: 'exe', description: '' })

async function refresh() {
  loading.value = true
  try {
    const resp = await stageApi.list()
    stages.value = resp.data?.data?.stages || []
  } catch { /* ignore */ }
  finally { loading.value = false }
}

function stageUrl(s: Stage) {
  return `/stage/${s.name}`
}

async function copyUrl(s: Stage) {
  const url = `${window.location.origin}/stage/${s.name}`
  await navigator.clipboard.writeText(url)
}

function editStage(s: Stage) {
  editTarget.value = s
  form.value = { name: s.name, type: s.type, description: s.description || '' }
}

async function deleteStage(s: Stage) {
  if (!confirm(`Delete stage "${s.name}"?`)) return
  try {
    await stageApi.delete(s.id)
    await refresh()
  } catch { /* ignore */ }
}

async function saveStage() {
  saving.value = true
  try {
    if (editTarget.value) {
      await stageApi.update(editTarget.value.id, form.value)
    } else {
      await stageApi.create(form.value)
    }
    closeModal()
    await refresh()
  } catch { /* ignore */ }
  finally { saving.value = false }
}

function closeModal() {
  showCreate.value = false
  editTarget.value = null
  form.value = { name: '', type: 'exe', description: '' }
}

function relTime(ts: string) {
  if (!ts) return '—'
  const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (sec < 60)   return `${sec}s ago`
  if (sec < 3600) return `${Math.floor(sec/60)}m ago`
  if (sec < 86400)return `${Math.floor(sec/3600)}h ago`
  return `${Math.floor(sec/86400)}d ago`
}

onMounted(refresh)
</script>

<style scoped>
.form-label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
.type-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-family: 'JetBrains Mono', monospace;
  background: var(--bg-overlay);
  color: var(--text-secondary);
}
.type-badge.exe, .type-badge.dll { color: var(--orange); }
.type-badge.ps1 { color: var(--cyan); }
.type-badge.raw { color: var(--red); }
</style>
