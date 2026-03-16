<template>
  <Layout>
    <div class="p-6">
      <!-- Header -->
      <div class="flex items-center gap-4 mb-6">
        <RouterLink to="/cluster" class="text-gray-500 hover:text-gray-800">
          <ArrowLeft :size="20" />
        </RouterLink>
        <h2 class="text-2xl font-bold text-gray-800">{{ $t('cluster.nodeDetail') }}</h2>
      </div>

      <!-- Loading / disabled -->
      <div v-if="disabled" class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-center gap-3">
        <AlertTriangle :size="20" class="text-yellow-500" />
        <span class="text-yellow-800">{{ $t('cluster.clusterDisabled') }}</span>
      </div>
      <div v-else-if="loading" class="text-gray-500 text-sm">{{ $t('common.loading') }}</div>
      <div v-else-if="notFound" class="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
        {{ $t('common.noData') }}
      </div>

      <template v-else-if="node">
        <!-- Node identity card -->
        <div class="bg-white rounded-lg shadow p-6 mb-4">
          <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-3">
              <span
                class="w-4 h-4 rounded-full flex-shrink-0"
                :class="{
                  'bg-green-500': node.health === 'healthy',
                  'bg-yellow-400': node.health === 'suspect',
                  'bg-red-500': node.health === 'dead',
                }"
              />
              <span class="font-mono text-base font-semibold text-gray-800">{{ node.node_id }}</span>
              <span v-if="node.is_self" class="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">
                {{ $t('cluster.isSelf') }}
              </span>
            </div>
            <button
              v-if="!node.is_self"
              @click="confirmRemove"
              class="px-3 py-1.5 text-sm text-red-600 border border-red-300 rounded hover:bg-red-50 transition-colors"
            >{{ $t('cluster.removeNode') }}</button>
          </div>

          <dl class="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div>
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.role') }}</dt>
              <dd class="font-medium" :class="roleColor(node.role)">{{ roleLabel(node.role) }}</dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.health') }}</dt>
              <dd class="font-medium" :class="healthColor(node.health)">{{ healthLabel(node.health) }}</dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.term') }}</dt>
              <dd class="font-mono">{{ node.term }}</dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.addr') }}</dt>
              <dd class="font-mono text-xs">{{ node.addr || '—' }}</dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.rulesVersion') }}</dt>
              <dd class="font-mono">{{ node.rules_version }}</dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.configVersion') }}</dt>
              <dd class="font-mono">{{ node.config_version }}</dd>
            </div>
            <div v-if="node.last_seen_ms">
              <dt class="text-xs text-gray-500 mb-1">{{ $t('cluster.lastSeen') }}</dt>
              <dd class="font-mono text-xs">{{ formatAge(node.last_seen_ms) }}</dd>
            </div>
          </dl>
        </div>
      </template>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ArrowLeft, AlertTriangle } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import { clusterApi } from '../api/index'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

const loading = ref(true)
const disabled = ref(false)
const notFound = ref(false)
const node = ref<any>(null)

const nodeId = route.params.id as string

async function load() {
  loading.value = true
  disabled.value = false
  notFound.value = false
  try {
    const res = await clusterApi.getNode(nodeId)
    node.value = res.data
  } catch (e: any) {
    if (e.response?.status === 404) {
      const msg: string = e.response?.data?.error ?? ''
      if (msg.includes('cluster not enabled')) {
        disabled.value = true
      } else {
        notFound.value = true
      }
    }
  } finally {
    loading.value = false
  }
}

async function confirmRemove() {
  if (!confirm(t('cluster.confirmRemove'))) return
  try {
    await clusterApi.removeNode(nodeId)
    router.push('/cluster')
  } catch {
    // ignore
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
