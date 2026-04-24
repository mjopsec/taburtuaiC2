import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { agentApi, serverApi } from '@/api'
import type { Agent, Stats } from '@/api/types'

export const useAgentStore = defineStore('agents', () => {
  const agents      = ref<Agent[]>([])
  const stats       = ref<Stats | null>(null)
  const loading     = ref(false)
  const error       = ref<string | null>(null)
  const lastRefresh = ref<Date | null>(null)

  const online  = computed(() => agents.value.filter(a => a.status === 'online'))
  const offline = computed(() => agents.value.filter(a => a.status === 'offline'))
  const dormant = computed(() => agents.value.filter(a => a.status === 'dormant'))

  async function fetch() {
    loading.value = true
    error.value   = null
    try {
      const r = await agentApi.list()
      agents.value  = r.data?.data?.agents ?? []
      lastRefresh.value = new Date()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } }; message?: string }
      error.value = err?.response?.data?.error ?? err?.message ?? 'Failed to fetch agents'
    } finally {
      loading.value = false
    }
  }

  async function fetchStats() {
    try {
      const r = await serverApi.stats()
      if (r.data?.data) stats.value = r.data.data
    } catch { /* ignore */ }
  }

  async function remove(id: string) {
    await agentApi.del(id)
    agents.value = agents.value.filter(a => a.id !== id)
  }

  function byId(id: string): Agent | undefined {
    return agents.value.find(a => a.id === id)
  }

  return { agents, stats, loading, error, lastRefresh, online, offline, dormant,
           fetch, fetchStats, remove, byId }
})
