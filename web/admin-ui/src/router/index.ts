import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/login', component: () => import('../views/Login.vue'), meta: { public: true } },
  { path: '/dashboard', component: () => import('../views/Dashboard.vue') },
  { path: '/hosts', component: () => import('../views/Hosts.vue') },
  { path: '/ip-rules', component: () => import('../views/IpRules.vue') },
  { path: '/url-rules', component: () => import('../views/UrlRules.vue') },
  { path: '/security-events', component: () => import('../views/SecurityEvents.vue') },
  { path: '/custom-rules', component: () => import('../views/CustomRules.vue') },
  { path: '/certificates', component: () => import('../views/Certificates.vue') },
  { path: '/cc-protection', component: () => import('../views/CCProtection.vue') },
  { path: '/notifications', component: () => import('../views/Notifications.vue') },
  { path: '/settings', component: () => import('../views/Settings.vue') },
  // Phase 6: CrowdSec
  { path: '/crowdsec-settings', component: () => import('../views/CrowdSecSettings.vue') },
  { path: '/crowdsec-decisions', component: () => import('../views/CrowdSecDecisions.vue') },
  { path: '/crowdsec-stats', component: () => import('../views/CrowdSecStats.vue') },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to, _from, next) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isLoggedIn) {
    next('/login')
  } else if (to.path === '/login' && auth.isLoggedIn) {
    next('/dashboard')
  } else {
    next()
  }
})

export default router
