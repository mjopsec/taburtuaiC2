<template>
  <span :class="['status-badge', cls]">
    <span class="badge-dot" :style="`background:${color}`" />
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string }>()

const cfg = computed(() => {
  switch (props.status) {
    case 'completed': return { color: 'var(--green)',  cls: 'online',  label: 'Completed' }
    case 'executing': return { color: 'var(--orange)', cls: 'dormant', label: 'Executing' }
    case 'pending':   return { color: 'var(--cyan)',   cls: 'pending', label: 'Pending'   }
    case 'failed':    return { color: 'var(--red)',    cls: 'offline', label: 'Failed'    }
    default:          return { color: 'var(--text-muted)', cls: '', label: props.status }
  }
})

const color = computed(() => cfg.value.color)
const cls   = computed(() => cfg.value.cls)
const label = computed(() => cfg.value.label)
</script>
