<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-2xl font-bold text-gray-800 mb-2">{{ $t('cluster.tokenTitle') }}</h2>
      <p class="text-sm text-gray-500 mb-6">{{ $t('cluster.tokenSubtitle') }}</p>

      <!-- Cluster disabled -->
      <div v-if="disabled" class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-center gap-3">
        <AlertTriangle :size="20" class="text-yellow-500" />
        <span class="text-yellow-800">{{ $t('cluster.clusterDisabled') }}</span>
      </div>

      <template v-else>
        <!-- Generate form -->
        <div class="bg-white rounded-lg shadow p-6 mb-6">
          <h3 class="text-base font-semibold text-gray-700 mb-4">{{ $t('cluster.generateToken') }}</h3>
          <div class="flex items-end gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('cluster.ttlLabel') }}</label>
              <input
                v-model.number="ttlHours"
                type="number"
                min="1"
                max="720"
                class="w-28 border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500 text-sm"
              />
            </div>
            <button
              @click="generate"
              :disabled="generating"
              class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              {{ generating ? $t('common.loading') : $t('cluster.generateToken') }}
            </button>
          </div>
          <p v-if="errorMsg" class="mt-2 text-sm text-red-600">{{ errorMsg }}</p>
        </div>

        <!-- Token display -->
        <div class="bg-white rounded-lg shadow p-6">
          <h3 class="text-base font-semibold text-gray-700 mb-4">{{ $t('cluster.tokenValue') }}</h3>

          <div v-if="!token" class="text-sm text-gray-500 italic">{{ $t('cluster.noToken') }}</div>

          <template v-else>
            <div class="bg-gray-900 rounded-lg p-4 mb-3 font-mono text-xs text-green-400 break-all select-all">
              {{ token }}
            </div>
            <div class="flex items-center gap-3">
              <button
                @click="copy"
                class="flex items-center gap-2 px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 rounded transition-colors"
              >
                <Copy :size="14" />
                {{ copied ? $t('cluster.tokenCopied') : $t('cluster.copyToken') }}
              </button>
              <span class="text-xs text-gray-400">TTL: {{ ttlHours }}h</span>
            </div>
            <p class="mt-3 text-xs text-gray-500 bg-gray-50 border border-gray-200 rounded p-3 font-mono">
              {{ $t('cluster.tokenHint') }}
            </p>
          </template>
        </div>
      </template>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { AlertTriangle, Copy } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import { clusterApi } from '../api/index'

const { t } = useI18n()

const disabled = ref(false)
const generating = ref(false)
const token = ref<string | null>(null)
const ttlHours = ref(1)
const copied = ref(false)
const errorMsg = ref('')

async function checkCluster() {
  try {
    await clusterApi.status()
  } catch (e: any) {
    if (e.response?.status === 404) disabled.value = true
  }
}

async function generate() {
  generating.value = true
  errorMsg.value = ''
  token.value = null
  try {
    const res = await clusterApi.generateToken(ttlHours.value * 3_600_000)
    token.value = res.data.token
  } catch (e: any) {
    const msg: string = e.response?.data?.error ?? t('common.noData')
    if (msg.includes('CA key not available')) {
      errorMsg.value = t('cluster.tokenMainOnly')
    } else {
      errorMsg.value = msg
    }
  } finally {
    generating.value = false
  }
}

async function copy() {
  if (!token.value) return
  try {
    await navigator.clipboard.writeText(token.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    // fallback: select the text manually
  }
}

onMounted(checkCluster)
</script>
