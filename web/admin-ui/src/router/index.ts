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
  { path: '/observations', component: () => import('../views/Observations.vue') },
  { path: '/custom-rules', component: () => import('../views/CustomRules.vue') },
  { path: '/certificates', component: () => import('../views/Certificates.vue') },
  { path: '/cc-protection', component: () => import('../views/CCProtection.vue') },
  { path: '/notifications', component: () => import('../views/Notifications.vue') },
  { path: '/audit-log', component: () => import('../views/AuditLog.vue') },
  { path: '/settings', component: () => import('../views/Settings.vue') },
  // Phase 6: CrowdSec
  { path: '/crowdsec-settings', component: () => import('../views/CrowdSecSettings.vue') },
  { path: '/crowdsec-decisions', component: () => import('../views/CrowdSecDecisions.vue') },
  { path: '/crowdsec-stats', component: () => import('../views/CrowdSecStats.vue') },
  // Phase 8: Cluster
  { path: '/cluster', component: () => import('../views/ClusterOverview.vue') },
  { path: '/cluster/nodes/:id', component: () => import('../views/ClusterNodeDetail.vue') },
  { path: '/cluster/tokens', component: () => import('../views/ClusterTokens.vue') },
  { path: '/cluster/sync', component: () => import('../views/ClusterSync.vue') },
  // Phase 7 rule management (`/rules-management`, `/rule-sources`,
  // `/bot-management`) is deliberately unrouted: the three views call API routes
  // that do not exist and silently fall back to demo data, and the subsystem they
  // present (`waf_engine::RuleManager`) is never loaded by the daemon. The views
  // remain in `src/views/` — this removes the entry, not the work. An old
  // bookmark now lands on the catch-all below instead of a blank page.
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
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
