<template>
  <div class="flex h-screen bg-gray-100">
    <!-- Sidebar -->
    <aside class="w-64 bg-gray-900 text-white flex flex-col">
      <div class="px-6 py-4 border-b border-gray-700">
        <h1 class="text-lg font-bold text-white">PRX-WAF</h1>
        <p class="text-xs text-gray-400">Admin Panel</p>
      </div>
      <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <NavItem to="/dashboard" icon="📊">Dashboard</NavItem>
        <NavItem to="/hosts" icon="🌐">Hosts</NavItem>
        <NavItem to="/ip-rules" icon="🔒">IP Rules</NavItem>
        <NavItem to="/url-rules" icon="🔗">URL Rules</NavItem>
        <NavItem to="/security-events" icon="⚠️">Security Events</NavItem>
        <NavItem to="/custom-rules" icon="📝">Custom Rules</NavItem>
        <NavItem to="/certificates" icon="🔐">SSL Certificates</NavItem>
        <NavItem to="/cc-protection" icon="🛡️">CC Protection</NavItem>
        <NavItem to="/notifications" icon="🔔">Notifications</NavItem>
        <NavItem to="/settings" icon="⚙️">Settings</NavItem>
        <div class="pt-2 pb-1 px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">CrowdSec</div>
        <NavItem to="/crowdsec-settings" icon="🌩️">CS Settings</NavItem>
        <NavItem to="/crowdsec-decisions" icon="🚫">CS Decisions</NavItem>
        <NavItem to="/crowdsec-stats" icon="📈">CS Stats</NavItem>
      </nav>
      <div class="px-4 py-3 border-t border-gray-700">
        <div class="flex items-center justify-between">
          <span class="text-sm text-gray-300">{{ auth.username }}</span>
          <button
            @click="handleLogout"
            class="text-xs text-gray-400 hover:text-white transition-colors"
          >Logout</button>
        </div>
      </div>
    </aside>

    <!-- Main content -->
    <main class="flex-1 overflow-y-auto">
      <slot />
    </main>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import NavItem from './NavItem.vue'

const auth = useAuthStore()
const router = useRouter()

async function handleLogout() {
  await auth.logout()
  router.push('/login')
}
</script>
