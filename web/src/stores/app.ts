import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  const apiKey   = ref(localStorage.getItem('c2_api_key') ?? '')
  const serverOk = ref(true)
  const sidebarCollapsed = ref(false)

  function setApiKey(key: string) {
    apiKey.value = key
    localStorage.setItem('c2_api_key', key)
  }

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  return { apiKey, serverOk, sidebarCollapsed, setApiKey, toggleSidebar }
})
