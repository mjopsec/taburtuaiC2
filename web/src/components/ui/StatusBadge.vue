<template>
  <span :class="['status-badge', status]">
    <span class="badge-dot" :style="`background:var(--status-${status})`" />
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string }>()

const label = computed(() => {
  switch (props.status) {
    case 'online':  return 'Online'
    case 'offline': return 'Offline'
    case 'dormant': return 'Dormant'
    default:        return props.status
  }
})
</script>
