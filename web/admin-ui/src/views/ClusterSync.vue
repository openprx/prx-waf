<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-2">
        <h2 class="text-2xl font-bold text-gray-800">{{ $t('cluster.syncTitle') }}</h2>
        <button
          @click="load"
          class="flex items-center gap-2 px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
        >
          <RefreshCw :size="14" />{{ $t('common.refresh') }}
        </button>
      </div>
      <p class="text-sm text-gray-500 mb-6">{{ $t('cluster.syncSubtitle') }}</p>

      <!-- Cluster disabled -->
      <div v-if="disabled" class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-center gap-3">
        <AlertTriangle :size="20" class="text-yellow-500" />
        <span class="text-yellow-800">{{ $t('cluster.syncNoCluster') }}</span>
      </div>

      <div v-else-if="loading" class="text-gray-500 text-sm">{{ $t('common.loading') }}</div>

      <template v-else-if="status">
        <!-- Drift alert -->
        <div
          v-if="hasDrift"
          class="bg-orange-50 border border-orange-200 rounded-lg p-4 mb-4 flex items-center gap-3"
        >
          <AlertTriangle :size="18" class="text-orange-500 flex-shrink-0" />
          <span class="text-orange-800 text-sm">{{ $t('cluster.syncDriftAlert') }}</span>
        </div>

        <!-- Sync table -->
        <div class="bg-white rounded-lg shadow overflow-hidden">
          <table class="w-full text-sm">
            <thead class="bg-gray-50 text-xs text-gray-500 uppercase tracking-wider">
              <tr>
                <th class="px-6 py-3 text-left">{{ $t('cluster.nodeId') }}</th>
                <th class="px-6 py-3 text-left">{{ $t('cluster.role') }}</th>
                <th class="px-6 py-3 text-left">{{ $t('cluster.syncRulesVersion') }}</th>
                <th class="px-6 py-3 text-left">{{ $t('cluster.syncConfigVersion') }}</th>
                <th class="px-6 py-3 text-left">{{ $t('cluster.syncDrift') }}</th>
                <th class="px-6 py-3 text-left">{{ $t('cluster.health') }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              <tr
                v-for="node in status.nodes"
                :key="node.node_id"
                class="hover:bg-gray-50"
              >
                <td class="px-6 py-3">
                  <div class="flex items-center gap-2">
                    <span class="font-mono text-xs">{{ node.node_id }}</span>
                    <span v-if="node.is_self" class="text-xs bg-blue-100 text-blue-600 px-1.5 py-0.5 rounded">
                      {{ $t('cluster.isSelf') }}
                    </span>
                  </div>
                </td>
                <td class="px-6 py-3">
                  <span :class="roleColor(node.role)" class="font-medium">{{ roleLabel(node.role) }}</span>
                </td>
                <td class="px-6 py-3 font-mono text-xs">
                  {{ node.rules_version }}
                </td>
                <td class="px-6 py-3 font-mono text-xs">
                  {{ node.config_version }}
                </td>
                <td class="px-6 py-3">
                  <span
                    v-if="rulesDrift(node)"
                    class="text-xs text-orange-600 font-medium"
                  >Δ {{ rulesDrift(node) }}</span>
                  <span v-else class="text-xs text-green-600">{{ $t('cluster.syncInSync') }}</span>
                </td>
                <td class="px-6 py-3">
                  <span :class="healthColor(node.health)" class="text-xs font-medium">
                    {{ healthLabel(node.health) }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Footer: master rules version -->
        <p class="mt-3 text-xs text-gray-500">
          Master rules version: <span class="font-mono">{{ status.rules_version }}</span>
          · Config version: <span class="font-mono">{{ status.config_version }}</span>
          · Term: <span class="font-mono">{{ status.term }}</span>
        </p>
      </template>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { AlertTriangle, RefreshCw } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import { clusterApi } from '../api/index'

const { t } = useI18n()

const loading = ref(true)
const disabled = ref(false)
const status = ref<any>(null)

const hasDrift = computed(() => {
  if (!status.value) return false
  const master = status.value.rules_version as number
  return status.value.nodes.some((n: any) => !n.is_self && n.rules_version !== 0 && n.rules_version !== master)
})

async function load() {
  loading.value = true
  disabled.value = false
  try {
    const res = await clusterApi.status()
    status.value = res.data
  } catch (e: any) {
    if (e.response?.status === 404) disabled.value = true
  } finally {
    loading.value = false
  }
}

function rulesDrift(node: any): number | null {
  if (!status.value || node.is_self || node.rules_version === 0) return null
  const delta = status.value.rules_version - node.rules_version
  return delta !== 0 ? delta : null
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

onMounted(load)
</script>
