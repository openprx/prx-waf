<template>
  <div class="flex h-screen bg-gray-100">
    <!-- Sidebar -->
    <aside class="w-64 bg-gray-900 text-white flex flex-col">
      <div class="px-6 py-4 border-b border-gray-700">
        <h1 class="text-lg font-bold text-white">PRX-WAF</h1>
        <p class="text-xs text-gray-400">{{ $t('auth.adminPanel') }}</p>
      </div>
      <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <NavItem to="/dashboard" :icon="LayoutDashboard">{{ $t('nav.dashboard') }}</NavItem>
        <NavItem to="/hosts" :icon="Globe">{{ $t('nav.hosts') }}</NavItem>
        <NavItem to="/ip-rules" :icon="Shield">{{ $t('nav.ipRules') }}</NavItem>
        <NavItem to="/url-rules" :icon="LinkIcon">{{ $t('nav.urlRules') }}</NavItem>
        <NavItem to="/security-events" :icon="AlertTriangle">{{ $t('nav.securityEvents') }}</NavItem>
        <NavItem to="/custom-rules" :icon="FileEdit">{{ $t('nav.customRules') }}</NavItem>
        <NavItem to="/certificates" :icon="Lock">{{ $t('nav.certificates') }}</NavItem>
        <NavItem to="/cc-protection" :icon="ShieldCheck">{{ $t('nav.ccProtection') }}</NavItem>
        <NavItem to="/notifications" :icon="Bell">{{ $t('nav.notifications') }}</NavItem>
        <NavItem to="/settings" :icon="Settings">{{ $t('nav.settings') }}</NavItem>
        <div class="pt-2 pb-1 px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{{ $t('nav.cluster') }}</div>
        <NavItem to="/cluster" :icon="Network">{{ $t('nav.clusterOverview') }}</NavItem>
        <NavItem to="/cluster/tokens" :icon="Key">{{ $t('nav.clusterTokens') }}</NavItem>
        <NavItem to="/cluster/sync" :icon="RefreshCw">{{ $t('nav.clusterSync') }}</NavItem>
        <div class="pt-2 pb-1 px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{{ $t('nav.crowdsec') }}</div>
        <NavItem to="/crowdsec-settings" :icon="Cloud">{{ $t('nav.csSettings') }}</NavItem>
        <NavItem to="/crowdsec-decisions" :icon="Ban">{{ $t('nav.csDecisions') }}</NavItem>
        <NavItem to="/crowdsec-stats" :icon="BarChart3">{{ $t('nav.csStats') }}</NavItem>
        <div class="pt-2 pb-1 px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{{ $t('nav.rules') }}</div>
        <NavItem to="/rules-management" :icon="BookOpen">{{ $t('nav.ruleManager') }}</NavItem>
        <NavItem to="/rule-sources" :icon="GitBranch">{{ $t('nav.ruleSources') }}</NavItem>
        <NavItem to="/bot-management" :icon="BotIcon">{{ $t('nav.botDetection') }}</NavItem>
      </nav>
      <div class="px-4 py-3 border-t border-gray-700 space-y-2">
        <!-- Language switcher -->
        <div class="flex items-center gap-2">
          <Languages :size="14" class="text-gray-400 flex-shrink-0" />
          <select
            v-model="currentLocale"
            @change="changeLocale"
            class="flex-1 bg-gray-800 text-gray-300 text-xs rounded px-2 py-1 border border-gray-700 focus:outline-none focus:border-gray-500"
          >
            <option value="en">English</option>
            <option value="zh">中文</option>
            <option value="ru">Русский</option>
            <option value="ka">ქართული</option>
          </select>
        </div>
        <!-- User row -->
        <div class="flex items-center justify-between">
          <span class="text-sm text-gray-300">{{ auth.username }}</span>
          <button
            @click="handleLogout"
            class="text-xs text-gray-400 hover:text-white transition-colors"
          >{{ $t('common.logout') }}</button>
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
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'
import NavItem from './NavItem.vue'
import {
  LayoutDashboard,
  Globe,
  Shield,
  Link as LinkIcon,
  AlertTriangle,
  FileEdit,
  Lock,
  ShieldCheck,
  Bell,
  Settings,
  Cloud,
  Ban,
  BarChart3,
  BookOpen,
  GitBranch,
  Bot as BotIcon,
  Languages,
  Network,
  Key,
  RefreshCw,
} from 'lucide-vue-next'

const auth = useAuthStore()
const router = useRouter()
const { locale } = useI18n()

const currentLocale = ref(locale.value)

function changeLocale() {
  locale.value = currentLocale.value
  localStorage.setItem('locale', currentLocale.value)
}

async function handleLogout() {
  await auth.logout()
  router.push('/login')
}
</script>
