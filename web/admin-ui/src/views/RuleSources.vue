<template>
  <Layout>
    <div class="p-6">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('ruleSources.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('ruleSources.subtitle') }}</p>
        </div>
        <div class="flex gap-2">
          <button @click="syncAll" :disabled="syncing" class="btn-secondary">
            {{ syncing ? $t('ruleSources.syncing') : $t('ruleSources.syncAll') }}
          </button>
          <button @click="showAddModal = true" class="btn-primary">{{ $t('ruleSources.addSource') }}</button>
        </div>
      </div>

      <!-- Sources list -->
      <div class="space-y-3">
        <!-- Built-in sources -->
        <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div class="px-4 py-3 bg-gray-50 border-b">
            <h3 class="font-medium text-gray-700 text-sm">{{ $t('ruleSources.builtinSources') }}</h3>
          </div>
          <div class="divide-y divide-gray-100">
            <div v-for="src in builtinSources" :key="src.name" class="px-4 py-3 flex items-center justify-between">
              <div class="flex items-center gap-3">
                <span class="w-2 h-2 rounded-full bg-green-400"></span>
                <div>
                  <div class="font-medium text-sm text-gray-900">{{ src.name }}</div>
                  <div class="text-xs text-gray-500">{{ src.description }}</div>
                </div>
              </div>
              <div class="flex items-center gap-3">
                <span class="text-xs text-gray-500">{{ src.count }} {{ $t('ruleSources.rules') }}</span>
                <span class="px-2 py-0.5 bg-purple-100 text-purple-700 rounded text-xs font-medium">{{ $t('ruleSources.builtin') }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Configured sources -->
        <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div class="px-4 py-3 bg-gray-50 border-b">
            <h3 class="font-medium text-gray-700 text-sm">{{ $t('ruleSources.configuredSources') }}</h3>
          </div>
          <div v-if="sources.length === 0" class="px-4 py-8 text-center text-gray-400 text-sm">
            {{ $t('ruleSources.noSources') }}
          </div>
          <div v-else class="divide-y divide-gray-100">
            <div v-for="src in sources" :key="src.name" class="px-4 py-3">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                  <span :class="src.enabled ? 'bg-green-400' : 'bg-gray-300'" class="w-2 h-2 rounded-full"></span>
                  <div>
                    <div class="font-medium text-sm text-gray-900">{{ src.name }}</div>
                    <div class="text-xs text-gray-500 font-mono truncate max-w-md">{{ src.url || src.path }}</div>
                  </div>
                </div>
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs font-medium">{{ src.format }}</span>
                  <span class="text-xs text-gray-400">{{ src.lastUpdated ? $t('ruleSources.updated') + formatDate(src.lastUpdated) : $t('ruleSources.neverSynced') }}</span>
                  <button @click="syncSource(src.name)" class="text-xs text-blue-600 hover:text-blue-800 px-2 py-1 border border-blue-200 rounded">
                    {{ $t('common.sync') }}
                  </button>
                  <button @click="removeSource(src.name)" class="text-xs text-red-600 hover:text-red-800 px-2 py-1 border border-red-200 rounded">
                    {{ $t('common.remove') }}
                  </button>
                </div>
              </div>
              <div v-if="src.error" class="mt-2 text-xs text-red-600 bg-red-50 rounded px-2 py-1">
                {{ $t('ruleSources.error') }}{{ src.error }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Add source modal -->
      <div v-if="showAddModal" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="showAddModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4">
          <div class="px-6 py-4 border-b">
            <h3 class="font-semibold text-gray-900">{{ $t('ruleSources.addSourceTitle') }}</h3>
          </div>
          <div class="px-6 py-4 space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('ruleSources.sourceName') }}</label>
              <input v-model="newSource.name" type="text" class="input w-full" placeholder="my-rules" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('ruleSources.sourceType') }}</label>
              <select v-model="newSource.type" class="input w-full">
                <option value="remote_url">{{ $t('ruleSources.remoteUrl') }}</option>
                <option value="local_dir">{{ $t('ruleSources.localDir') }}</option>
                <option value="local_file">{{ $t('ruleSources.localFile') }}</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">
                {{ newSource.type === 'remote_url' ? $t('ruleSources.url') : $t('ruleSources.path') }}
              </label>
              <input
                v-model="newSource.url"
                type="text"
                class="input w-full"
                :placeholder="newSource.type === 'remote_url' ? 'https://example.com/rules.yaml' : '/etc/prx-waf/rules/'"
              />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('common.format') }}</label>
              <select v-model="newSource.format" class="input w-full">
                <option value="yaml">YAML</option>
                <option value="json">JSON</option>
                <option value="modsec">ModSecurity</option>
              </select>
            </div>
            <div v-if="newSource.type === 'remote_url'">
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('ruleSources.updateInterval') }}</label>
              <input v-model.number="newSource.updateInterval" type="number" class="input w-full" placeholder="86400" />
            </div>
          </div>
          <div class="px-6 py-4 border-t flex gap-2 justify-end">
            <button @click="showAddModal = false" class="btn-secondary">{{ $t('common.cancel') }}</button>
            <button @click="addSource" :disabled="!newSource.name || !newSource.url" class="btn-primary">{{ $t('ruleSources.addSource') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import Layout from '../components/Layout.vue'
import axios from 'axios'

const { t } = useI18n()

interface Source {
  name: string
  type: string
  url?: string
  path?: string
  format: string
  enabled: boolean
  lastUpdated?: string
  error?: string
}

const sources = ref<Source[]>([])
const syncing = ref(false)
const showAddModal = ref(false)

const builtinSources = [
  { name: 'builtin-owasp', description: 'OWASP CRS built-in rules (SQLi, XSS, RCE, traversal)', count: 15 },
  { name: 'builtin-bot', description: 'Bot detection patterns (scrapers, AI crawlers, headless browsers)', count: 31 },
  { name: 'builtin-scanner', description: 'Vulnerability scanner fingerprints (Nikto, sqlmap, etc.)', count: 19 },
]

const newSource = ref({
  name: '',
  type: 'remote_url',
  url: '',
  format: 'yaml',
  updateInterval: 86400,
})

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString()
}

async function loadSources() {
  try {
    const { data } = await axios.get('/api/rule-sources')
    sources.value = data.sources ?? []
  } catch {
    sources.value = []
  }
}

async function syncAll() {
  syncing.value = true
  try {
    await axios.post('/api/rule-sources/sync')
    await loadSources()
  } catch (e) {
    console.error('Sync failed', e)
  } finally {
    syncing.value = false
  }
}

async function syncSource(name: string) {
  try {
    await axios.post(`/api/rule-sources/${name}/sync`)
    await loadSources()
  } catch (e) {
    console.error('Sync failed', e)
  }
}

async function removeSource(name: string) {
  if (!confirm(t('ruleSources.confirmRemove', { name }))) return
  try {
    await axios.delete(`/api/rule-sources/${name}`)
    sources.value = sources.value.filter(s => s.name !== name)
  } catch (e) {
    console.error('Remove failed', e)
  }
}

async function addSource() {
  try {
    await axios.post('/api/rule-sources', {
      name: newSource.value.name,
      source_type: newSource.value.type,
      url: newSource.value.url,
      format: newSource.value.format,
      update_interval: newSource.value.updateInterval,
    })
    showAddModal.value = false
    newSource.value = { name: '', type: 'remote_url', url: '', format: 'yaml', updateInterval: 86400 }
    await loadSources()
  } catch (e) {
    console.error('Add failed', e)
  }
}

onMounted(loadSources)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 disabled:opacity-50; }
</style>
