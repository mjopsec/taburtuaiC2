<template>
  <aside class="sidebar">
    <!-- Brand -->
    <div class="sidebar-brand">
      <div class="sidebar-brand-icon">⚔</div>
      <div v-if="!collapsed">
        <div class="sidebar-brand-name">TABURTUAI</div>
        <div class="sidebar-brand-tag">C2 Framework v2.0</div>
      </div>
    </div>

    <!-- Navigation -->
    <nav class="sidebar-nav">
      <div class="nav-section">
        <div v-if="!collapsed" class="nav-label">Operations</div>
        <RouterLink v-for="item in navItems" :key="item.to"
          :to="item.to" custom v-slot="{ isActive, navigate }">
          <div :class="['nav-item', isActive && 'active']" @click="navigate">
            <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor" v-html="item.icon" />
            <span v-if="!collapsed">{{ item.label }}</span>
            <span v-if="!collapsed && item.badge" class="nav-badge" :class="item.badgeClass">
              {{ item.badge }}
            </span>
          </div>
        </RouterLink>
      </div>
    </nav>

    <!-- Footer -->
    <div class="sidebar-footer">
      <div class="server-status">
        <div :class="['status-dot', !appStore.serverOk && 'offline']" />
        <span v-if="!collapsed" class="text-muted text-sm">
          {{ appStore.serverOk ? 'Server connected' : 'Disconnected' }}
        </span>
      </div>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAppStore } from '@/stores/app'
import { useAgentStore } from '@/stores/agents'

const appStore   = useAppStore()
const agentStore = useAgentStore()
const collapsed  = computed(() => appStore.sidebarCollapsed)

const navItems = computed(() => [
  {
    to: '/', label: 'Dashboard',
    icon: '<path d="M1 2.75A.75.75 0 011.75 2h3.5a.75.75 0 01.75.75v3.5A.75.75 0 015.25 7h-3.5A.75.75 0 011 6.25zm0 7A.75.75 0 011.75 9h3.5a.75.75 0 01.75.75v3.5a.75.75 0 01-.75.75h-3.5A.75.75 0 011 13.25zm7-7A.75.75 0 018.75 2h3.5a.75.75 0 01.75.75v3.5A.75.75 0 0112.25 7h-3.5A.75.75 0 018 6.25zm0 7A.75.75 0 018.75 9h3.5a.75.75 0 01.75.75v3.5a.75.75 0 01-.75.75h-3.5A.75.75 0 018 13.25z"/>',
  },
  {
    to: '/agents', label: 'Agents',
    badge: agentStore.online.length || undefined,
    badgeClass: 'green',
    icon: '<path d="M8 0a8 8 0 110 16A8 8 0 018 0zm0 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zm0 2a2 2 0 110 4 2 2 0 010-4zm0 5.5c2.07 0 3.76.695 4.583 1.794A5.496 5.496 0 018 13.5a5.496 5.496 0 01-4.583-2.206C4.24 10.195 5.93 9.5 8 9.5z"/>',
  },
  {
    to: '/commands', label: 'Commands',
    icon: '<path d="M2.75 2A1.75 1.75 0 001 3.75v8.5C1 13.216 1.784 14 2.75 14h10.5A1.75 1.75 0 0015 12.25v-8.5A1.75 1.75 0 0013.25 2H2.75zm.56 3.03a.75.75 0 011.06-1.06l2.5 2.5c.292.292.292.768 0 1.06l-2.5 2.5a.75.75 0 11-1.06-1.06L5.69 8 3.31 5.03v-.001zM7.5 9.25a.75.75 0 000 1.5h3.5a.75.75 0 000-1.5h-3.5z"/>',
  },
  {
    to: '/logs', label: 'Logs',
    icon: '<path d="M2 1.75A1.75 1.75 0 013.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0113.25 16h-9.5A1.75 1.75 0 012 14.25V1.75zm1.75-.25a.25.25 0 00-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 00.25-.25V4.664a.25.25 0 00-.073-.177l-2.914-2.914a.25.25 0 00-.177-.073H3.75zM4.5 6.75a.75.75 0 011.5 0v.01a.75.75 0 01-1.5 0v-.01zm0 3a.75.75 0 011.5 0v.01a.75.75 0 01-1.5 0v-.01zm0 3a.75.75 0 011.5 0v.01a.75.75 0 01-1.5 0v-.01zM7.5 5.5a.75.75 0 000 1.5h4a.75.75 0 000-1.5h-4zm0 3a.75.75 0 000 1.5h4a.75.75 0 000-1.5h-4zm0 3a.75.75 0 000 1.5h4a.75.75 0 000-1.5h-4z"/>',
  },
  {
    to: '/stages', label: 'Stages',
    icon: '<path d="M10.5 2.5a2.5 2.5 0 113.164 2.389 1 1 0 01-.164.111v4.25a.75.75 0 01-.75.75H2.5v1.25a.75.75 0 01-1.5 0v-3.5a.75.75 0 011.5 0V9H12V4.911a1 1 0 01-.164-.111A2.5 2.5 0 0110.5 2.5zM3.25 12.5a.75.75 0 01.75.75v.25h7.5v-.25a.75.75 0 011.5 0v1a.75.75 0 01-.75.75H3.25a.75.75 0 01-.75-.75v-1a.75.75 0 01.75-.75z"/>',
  },
])
</script>
