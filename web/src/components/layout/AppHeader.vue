<template>
  <header class="topbar">
    <!-- Sidebar toggle -->
    <button class="btn btn-ghost btn-icon" @click="appStore.toggleSidebar()" title="Toggle sidebar">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M1 2.75A.75.75 0 011.75 2h12.5a.75.75 0 010 1.5H1.75A.75.75 0 011 2.75zm0 5A.75.75 0 011.75 7h12.5a.75.75 0 010 1.5H1.75A.75.75 0 011 7.75zm0 5A.75.75 0 011.75 12h12.5a.75.75 0 010 1.5H1.75A.75.75 0 011 12.75z"/>
      </svg>
    </button>

    <!-- Breadcrumb -->
    <div>
      <div class="topbar-title">{{ routeTitle }}</div>
      <div class="topbar-sub">{{ agentStore.lastRefresh ? 'Updated ' + relativeTime : 'Loading…' }}</div>
    </div>

    <div class="topbar-spacer" />

    <!-- Agent counts -->
    <div class="flex gap-2">
      <span class="badge online">
        <span class="badge-dot" style="background:var(--green)" />
        {{ agentStore.online.length }} online
      </span>
      <span v-if="agentStore.offline.length" class="badge offline">
        {{ agentStore.offline.length }} offline
      </span>
    </div>

    <!-- API Key -->
    <button class="btn btn-ghost btn-sm" @click="showApiKeyModal = true">
      <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
        <path d="M10.5 0a5.5 5.5 0 014.382 8.816L16 10.5v1.25a.75.75 0 01-.75.75H14v1.25a.75.75 0 01-.75.75H12v1.25a.75.75 0 01-.75.75h-2a.75.75 0 01-.75-.75v-2.061a5.5 5.5 0 012-10.939zM10.5 3a.75.75 0 000 1.5 2 2 0 012 2 .75.75 0 001.5 0 3.5 3.5 0 00-3.5-3.5z"/>
      </svg>
      API Key
    </button>

    <!-- Refresh -->
    <button class="btn btn-ghost btn-icon" @click="refresh()" :disabled="agentStore.loading" title="Refresh">
      <div v-if="agentStore.loading" class="loading-spinner" style="width:14px;height:14px" />
      <svg v-else width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M8 3a5 5 0 100 10A5 5 0 008 3zM1 8a7 7 0 1114 0A7 7 0 011 8z"/>
        <path d="M8 5.5a.75.75 0 01.75.75v2a.75.75 0 01-.75.75H6.75a.75.75 0 010-1.5H7.25V6.25A.75.75 0 018 5.5z"/>
      </svg>
    </button>
  </header>

  <!-- API Key Modal -->
  <div v-if="showApiKeyModal" class="modal-overlay" @click.self="showApiKeyModal = false">
    <div class="modal">
      <div class="modal-header">API Key Configuration</div>
      <div class="modal-body">
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">
          Set your API key to authenticate with the C2 server. Leave empty if auth is disabled.
        </p>
        <input v-model="apiKeyInput" class="input input-mono"
          type="password" placeholder="API key (leave blank if auth disabled)"
          @keyup.enter="saveKey" />
      </div>
      <div class="modal-footer">
        <button class="btn btn-ghost" @click="showApiKeyModal = false">Cancel</button>
        <button class="btn btn-primary" @click="saveKey">Save</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useAgentStore } from '@/stores/agents'
import { useAppStore } from '@/stores/app'

const agentStore = useAgentStore()
const appStore   = useAppStore()
const route      = useRoute()

const showApiKeyModal = ref(false)
const apiKeyInput     = ref(appStore.apiKey)

const routeTitles: Record<string, string> = {
  dashboard: 'Dashboard',
  agents:    'Agents',
  agent:     'Agent Detail',
  commands:  'Command History',
  logs:      'Server Logs',
  stages:    'Payload Stages',
}
const routeTitle = computed(() => routeTitles[route.name as string] ?? 'Taburtuai C2')

const relativeTime = computed(() => {
  if (!agentStore.lastRefresh) return ''
  const sec = Math.floor((Date.now() - agentStore.lastRefresh.getTime()) / 1000)
  if (sec < 60) return `${sec}s ago`
  return `${Math.floor(sec / 60)}m ago`
})

function saveKey() {
  appStore.setApiKey(apiKeyInput.value.trim())
  showApiKeyModal.value = false
}

async function refresh() {
  await Promise.all([agentStore.fetch(), agentStore.fetchStats()])
}
</script>
