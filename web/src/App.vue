<template>
  <div :class="['app-shell', appStore.sidebarCollapsed && 'sidebar-collapsed']">
    <AppSidebar />
    <AppHeader />
    <main class="main-content">
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useAgentStore } from '@/stores/agents'
import { useAppStore } from '@/stores/app'
import AppSidebar from '@/components/layout/AppSidebar.vue'
import AppHeader from '@/components/layout/AppHeader.vue'

const agentStore = useAgentStore()
const appStore   = useAppStore()

let timer: ReturnType<typeof setInterval>

onMounted(async () => {
  await Promise.all([agentStore.fetch(), agentStore.fetchStats()])
  timer = setInterval(() => {
    agentStore.fetch()
    agentStore.fetchStats()
  }, 15_000)
})

onUnmounted(() => clearInterval(timer))
</script>
