<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold text-gray-800">{{ $t('cluster.overview') }}</h2>
        <button
          @click="load"
          class="flex items-center gap-2 px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
        >
          <RefreshCw :size="14" />{{ $t('common.refresh') }}
        </button>
      </div>

      <!-- Cluster disabled banner -->
      <div v-if="disabled" class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6 flex items-center gap-3">
        <AlertTriangle :size="20" class="text-yellow-500 flex-shrink-0" />
        <span class="text-yellow-800">{{ $t('cluster.clusterDisabled') }}</span>
      </div>

      <!-- Loading -->
      <div v-else-if="loading" class="text-gray-500 text-sm">{{ $t('cluster.loading') }}</div>

      <template v-else-if="status">
        <!-- Stats row -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatCard :label="$t('cluster.totalNodes')" :value="String(status.total_nodes)" color="blue" />
          <StatCard :label="$t('cluster.role')" :value="roleLabel(status.role)" color="green" />
          <StatCard :label="$t('cluster.term')" :value="String(status.term)" color="purple" />
          <StatCard :label="$t('cluster.rulesVersion')" :value="String(status.rules_version)" color="blue" />
        </div>

        <!-- Node cards -->
        <div class="bg-white rounded-lg shadow">
          <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <h3 class="text-lg font-semibold text-gray-700">{{ $t('cluster.nodeId') }}s</h3>
            <span class="text-sm text-gray-500">{{ status.listen_addr }}</span>
          </div>
          <div v-if="status.nodes.length === 0" class="px-6 py-8 text-center text-gray-500 text-sm">
            {{ $t('cluster.noNodes') }}
          </div>
          <div v-else class="divide-y divide-gray-100">
            <div
              v-for="node in status.nodes"
              :key="node.node_id"
              class="px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
            >
              <div class="flex items-center gap-4">
                <!-- Health dot -->
                <span
                  class="w-3 h-3 rounded-full flex-shrink-0"
                  :class="{
                    'bg-green-500': node.health === 'healthy',
                    'bg-yellow-400': node.health === 'suspect',
                    'bg-red-500': node.health === 'dead',
                  }"
                />
                <div>
                  <div class="flex items-center gap-2">
                    <span class="font-mono text-sm font-medium text-gray-800">{{ node.node_id }}</span>
                    <span v-if="node.is_self" class="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">
                      {{ $t('cluster.selfLabel') }}
                    </span>
                  </div>
                  <div class="text-xs text-gray-500 mt-0.5">{{ node.addr || '—' }}</div>
                </div>
              </div>
              <div class="flex items-center gap-6 text-sm">
                <div class="text-center">
                  <div class="text-xs text-gray-500">{{ $t('cluster.role') }}</div>
                  <div class="font-medium" :class="roleColor(node.role)">{{ roleLabel(node.role) }}</div>
                </div>
                <div class="text-center">
                  <div class="text-xs text-gray-500">{{ $t('cluster.health') }}</div>
                  <div class="font-medium" :class="healthColor(node.health)">{{ healthLabel(node.health) }}</div>
                </div>
                <div v-if="node.last_seen_ms" class="text-center">
                  <div class="text-xs text-gray-500">{{ $t('cluster.lastSeen') }}</div>
                  <div class="font-mono text-xs text-gray-700">{{ formatAge(node.last_seen_ms) }}</div>
                </div>
                <RouterLink
                  :to="`/cluster/nodes/${node.node_id}`"
                  class="text-blue-600 hover:text-blue-800 text-xs"
                >{{ $t('common.actions') }} →</RouterLink>
              </div>
            </div>
          </div>
        </div>
      </template>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { AlertTriangle, RefreshCw } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import StatCard from '../components/StatCard.vue'
import { clusterApi } from '../api/index'

const { t } = useI18n()

const loading = ref(true)
const disabled = ref(false)
const status = ref<any>(null)

async function load() {
  loading.value = true
  disabled.value = false
  try {
    const res = await clusterApi.status()
    status.value = res.data
  } catch (e: any) {
    if (e.response?.status === 404) {
      disabled.value = true
    }
  } finally {
    loading.value = false
  }
}

function roleLabel(role: string): string {
  const map: Record<string, string> = {
    main: t('cluster.main'),
    worker: t('cluster.worker'),
    candidate: t('cluster.candidate'),
  }
  return map[role] ?? role
}

function roleColor(role: string): string {
  if (role === 'main') return 'text-green-700'
  if (role === 'candidate') return 'text-yellow-600'
  return 'text-gray-700'
}

function healthLabel(h: string): string {
  if (h === 'healthy') return t('cluster.healthy')
  if (h === 'suspect') return t('cluster.suspect')
  return t('cluster.dead')
}

function healthColor(h: string): string {
  if (h === 'healthy') return 'text-green-600'
  if (h === 'suspect') return 'text-yellow-500'
  return 'text-red-600'
}

function formatAge(ms: number): string {
  const age = Date.now() - ms
  if (age < 1000) return `${age}${t('cluster.msAgo')}`
  return `${(age / 1000).toFixed(1)}s ago`
}

onMounted(load)
</script>
