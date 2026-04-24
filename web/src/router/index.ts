import { createRouter, createWebHistory } from 'vue-router'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/',           name: 'dashboard', component: () => import('@/views/Dashboard.vue') },
    { path: '/agents',     name: 'agents',    component: () => import('@/views/Agents.vue') },
    { path: '/agents/:id', name: 'agent',     component: () => import('@/views/AgentDetail.vue') },
    { path: '/commands',   name: 'commands',  component: () => import('@/views/CommandHistory.vue') },
    { path: '/logs',       name: 'logs',      component: () => import('@/views/Logs.vue') },
    { path: '/stages',     name: 'stages',    component: () => import('@/views/Stages.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})
