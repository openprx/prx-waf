<template>
  <Layout>
    <div class="p-6">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('rules.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('rules.manageRules') }}</p>
        </div>
        <div class="flex gap-2">
          <button @click="reloadRules" :disabled="loading" class="btn-secondary">
            {{ $t('rules.reloadRules') }}
          </button>
          <button @click="showImportModal = true" class="btn-primary">
            {{ $t('rules.importRules') }}
          </button>
        </div>
      </div>

      <!-- Stats bar -->
      <div class="grid grid-cols-4 gap-4 mb-6">
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-gray-900">{{ stats.total }}</div>
          <div class="text-sm text-gray-500">{{ $t('rules.totalRules') }}</div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-green-600">{{ stats.enabled }}</div>
          <div class="text-sm text-gray-500">{{ $t('rules.enabledRules') }}</div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-gray-400">{{ stats.disabled }}</div>
          <div class="text-sm text-gray-500">{{ $t('rules.disabledRules') }}</div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-blue-600">{{ Object.keys(stats.byCategory).length }}</div>
          <div class="text-sm text-gray-500">{{ $t('rules.categories') }}</div>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-white rounded-lg border border-gray-200 mb-4 p-4 flex flex-wrap gap-3">
        <input
          v-model="searchQuery"
          type="text"
          :placeholder="$t('rules.searchRules')"
          class="input flex-1 min-w-48"
        />
        <select v-model="filterCategory" class="input w-40">
          <option value="">{{ $t('rules.allCategories') }}</option>
          <option v-for="cat in categories" :key="cat" :value="cat">{{ cat }}</option>
        </select>
        <select v-model="filterSource" class="input w-40">
          <option value="">{{ $t('rules.allSources') }}</option>
          <option v-for="src in sources" :key="src" :value="src">{{ src }}</option>
        </select>
        <select v-model="filterStatus" class="input w-32">
          <option value="">{{ $t('rules.allStatus') }}</option>
          <option value="enabled">{{ $t('common.enabled') }}</option>
          <option value="disabled">{{ $t('common.disabled') }}</option>
        </select>
      </div>

      <!-- Rules table -->
      <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.ruleId') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('common.name') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.category') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('common.source') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.severity') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('security.action') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('common.status') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.ops') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-if="loading">
              <td colspan="8" class="px-4 py-8 text-center text-gray-500">{{ $t('rules.loadingRules') }}</td>
            </tr>
            <tr v-else-if="filteredRules.length === 0">
              <td colspan="8" class="px-4 py-8 text-center text-gray-400">{{ $t('rules.noRulesFound') }}</td>
            </tr>
            <tr
              v-for="rule in paginatedRules"
              :key="rule.id"
              class="hover:bg-gray-50 cursor-pointer"
              @click="selectedRule = rule"
            >
              <td class="px-4 py-3 font-mono text-xs text-gray-700">{{ rule.id }}</td>
              <td class="px-4 py-3 text-sm text-gray-900">{{ rule.name }}</td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">
                  {{ rule.category }}
                </span>
              </td>
              <td class="px-4 py-3 text-xs text-gray-500">{{ rule.source }}</td>
              <td class="px-4 py-3">
                <span
                  v-if="rule.severity"
                  :class="severityClass(rule.severity)"
                  class="px-2 py-0.5 rounded text-xs font-medium"
                >{{ rule.severity }}</span>
              </td>
              <td class="px-4 py-3">
                <span :class="actionClass(rule.action)" class="px-2 py-0.5 rounded text-xs font-medium">
                  {{ rule.action }}
                </span>
              </td>
              <td class="px-4 py-3">
                <span :class="rule.enabled ? 'text-green-600' : 'text-gray-400'" class="text-xs font-medium">
                  {{ rule.enabled ? $t('botManagement.enabled') : $t('botManagement.disabled') }}
                </span>
              </td>
              <td class="px-4 py-3">
                <button
                  @click.stop="toggleRule(rule)"
                  class="text-xs text-blue-600 hover:text-blue-800"
                >
                  {{ rule.enabled ? $t('rules.disable') : $t('rules.enable') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        <!-- Pagination -->
        <div class="px-4 py-3 border-t flex items-center justify-between text-sm text-gray-500">
          <span>{{ $t('rules.showing') }} {{ paginationStart }}–{{ paginationEnd }} {{ $t('rules.of') }} {{ filteredRules.length }} {{ $t('common.total').toLowerCase() }}</span>
          <div class="flex gap-1">
            <button @click="page--" :disabled="page <= 1" class="btn-page">{{ $t('common.prev') }}</button>
            <button @click="page++" :disabled="page >= pageCount" class="btn-page">{{ $t('common.next') }}</button>
          </div>
        </div>
      </div>

      <!-- Rule detail modal -->
      <div v-if="selectedRule" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="selectedRule = null">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden">
          <div class="px-6 py-4 border-b flex items-center justify-between">
            <h3 class="font-semibold text-gray-900">{{ selectedRule.name }}</h3>
            <button @click="selectedRule = null" class="text-gray-400 hover:text-gray-600">
              <X :size="20" />
            </button>
          </div>
          <div class="px-6 py-4 space-y-3 text-sm">
            <div class="grid grid-cols-2 gap-4">
              <div><span class="text-gray-500">ID:</span> <code class="text-xs bg-gray-100 px-1 rounded">{{ selectedRule.id }}</code></div>
              <div><span class="text-gray-500">{{ $t('rules.category') }}:</span> {{ selectedRule.category }}</div>
              <div><span class="text-gray-500">{{ $t('common.source') }}:</span> {{ selectedRule.source }}</div>
              <div><span class="text-gray-500">{{ $t('security.action') }}:</span>
                <span :class="actionClass(selectedRule.action)" class="px-2 py-0.5 rounded text-xs font-medium ml-1">{{ selectedRule.action }}</span>
              </div>
              <div><span class="text-gray-500">{{ $t('rules.severity') }}:</span> {{ selectedRule.severity ?? 'N/A' }}</div>
              <div><span class="text-gray-500">{{ $t('common.status') }}:</span>
                <span :class="selectedRule.enabled ? 'text-green-600' : 'text-gray-400'" class="font-medium ml-1">
                  {{ selectedRule.enabled ? $t('common.enabled') : $t('common.disabled') }}
                </span>
              </div>
            </div>
            <div v-if="selectedRule.description">
              <span class="text-gray-500">{{ $t('common.description') }}:</span>
              <p class="mt-1 text-gray-700">{{ selectedRule.description }}</p>
            </div>
            <div v-if="selectedRule.pattern">
              <span class="text-gray-500">{{ $t('botManagement.pattern') }}:</span>
              <pre class="mt-1 text-xs bg-gray-100 rounded p-2 overflow-x-auto">{{ selectedRule.pattern }}</pre>
            </div>
            <div v-if="selectedRule.tags?.length">
              <span class="text-gray-500">{{ $t('botManagement.tags') }}:</span>
              <span v-for="tag in selectedRule.tags" :key="tag" class="ml-1 px-2 py-0.5 bg-gray-100 rounded text-xs">{{ tag }}</span>
            </div>
          </div>
          <div class="px-6 py-4 border-t flex gap-2 justify-end">
            <button @click="toggleRule(selectedRule); selectedRule = null" class="btn-secondary">
              {{ selectedRule.enabled ? $t('rules.disable') + ' ' + $t('nav.ruleManager') : $t('rules.enable') + ' ' + $t('nav.ruleManager') }}
            </button>
            <button @click="selectedRule = null" class="btn-primary">{{ $t('common.close') }}</button>
          </div>
        </div>
      </div>

      <!-- Import modal -->
      <div v-if="showImportModal" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="showImportModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4">
          <div class="px-6 py-4 border-b">
            <h3 class="font-semibold text-gray-900">{{ $t('ruleImport.title') }}</h3>
          </div>
          <div class="px-6 py-4 space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('ruleImport.sourceLabel') }}</label>
              <input v-model="importSource" type="text" class="input w-full" :placeholder="$t('ruleImport.sourcePlaceholder')" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('ruleImport.formatLabel') }}</label>
              <select v-model="importFormat" class="input w-full">
                <option value="yaml">YAML</option>
                <option value="json">JSON</option>
                <option value="modsec">ModSecurity</option>
              </select>
            </div>
          </div>
          <div class="px-6 py-4 border-t flex gap-2 justify-end">
            <button @click="showImportModal = false" class="btn-secondary">{{ $t('common.cancel') }}</button>
            <button @click="importRules" class="btn-primary">{{ $t('common.import') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { X } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import axios from 'axios'

useI18n()

interface Rule {
  id: string
  name: string
  description?: string
  category: string
  source: string
  enabled: boolean
  action: string
  severity?: string
  pattern?: string
  tags?: string[]
}

interface RuleStats {
  total: number
  enabled: number
  disabled: number
  byCategory: Record<string, number>
  bySource: Record<string, number>
}

const rules = ref<Rule[]>([])
const loading = ref(false)
const selectedRule = ref<Rule | null>(null)
const showImportModal = ref(false)
const importSource = ref('')
const importFormat = ref('yaml')
const searchQuery = ref('')
const filterCategory = ref('')
const filterSource = ref('')
const filterStatus = ref('')
const page = ref(1)
const pageSize = 20

const stats = computed<RuleStats>(() => {
  const total = rules.value.length
  const enabled = rules.value.filter(r => r.enabled).length
  const byCategory: Record<string, number> = {}
  const bySource: Record<string, number> = {}
  for (const r of rules.value) {
    byCategory[r.category] = (byCategory[r.category] ?? 0) + 1
    bySource[r.source] = (bySource[r.source] ?? 0) + 1
  }
  return { total, enabled, disabled: total - enabled, byCategory, bySource }
})

const categories = computed(() => [...new Set(rules.value.map(r => r.category))].sort())
const sources = computed(() => [...new Set(rules.value.map(r => r.source))].sort())

const filteredRules = computed(() => {
  let list = rules.value
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter(r =>
      r.id.toLowerCase().includes(q) ||
      r.name.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q)
    )
  }
  if (filterCategory.value) list = list.filter(r => r.category === filterCategory.value)
  if (filterSource.value) list = list.filter(r => r.source === filterSource.value)
  if (filterStatus.value === 'enabled') list = list.filter(r => r.enabled)
  if (filterStatus.value === 'disabled') list = list.filter(r => !r.enabled)
  return list
})

const pageCount = computed(() => Math.ceil(filteredRules.value.length / pageSize))
const paginatedRules = computed(() => filteredRules.value.slice((page.value - 1) * pageSize, page.value * pageSize))
const paginationStart = computed(() => Math.min((page.value - 1) * pageSize + 1, filteredRules.value.length))
const paginationEnd = computed(() => Math.min(page.value * pageSize, filteredRules.value.length))

function severityClass(sev: string) {
  return {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
  }[sev] ?? 'bg-gray-100 text-gray-600'
}

function actionClass(action: string) {
  return {
    block: 'bg-red-100 text-red-700',
    log: 'bg-yellow-100 text-yellow-700',
    allow: 'bg-green-100 text-green-700',
  }[action] ?? 'bg-gray-100 text-gray-600'
}

async function loadRules() {
  loading.value = true
  try {
    const { data } = await axios.get('/api/rules/registry')
    rules.value = data.rules ?? []
  } catch {
    // Demo: show built-in rule stubs
    rules.value = [
      { id: 'OWASP-942100', name: 'SQL Injection via libinjection', category: 'sqli', source: 'builtin-owasp', enabled: true, action: 'block', severity: 'critical' },
      { id: 'OWASP-941100', name: 'XSS Attack via libinjection', category: 'xss', source: 'builtin-owasp', enabled: true, action: 'block', severity: 'critical' },
      { id: 'BOT-BAD-001', name: 'Scrapy web scraper', category: 'bot', source: 'builtin-bot', enabled: true, action: 'block', severity: 'high' },
      { id: 'SCAN-001', name: 'Nikto web scanner', category: 'scanner', source: 'builtin-scanner', enabled: true, action: 'block', severity: 'high' },
    ]
  } finally {
    loading.value = false
  }
}

async function reloadRules() {
  loading.value = true
  try {
    await axios.post('/api/rules/reload')
    await loadRules()
  } catch (e) {
    console.error('Reload failed', e)
  } finally {
    loading.value = false
  }
}

async function toggleRule(rule: Rule) {
  const newState = !rule.enabled
  try {
    await axios.patch(`/api/rules/registry/${rule.id}`, { enabled: newState })
    rule.enabled = newState
  } catch {
    rule.enabled = newState // optimistic
  }
}

async function importRules() {
  try {
    await axios.post('/api/rules/import', { source: importSource.value, format: importFormat.value })
    showImportModal.value = false
    await loadRules()
  } catch (e) {
    console.error('Import failed', e)
  }
}

onMounted(loadRules)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 disabled:opacity-50; }
.btn-page { @apply px-3 py-1 border border-gray-300 rounded text-sm hover:bg-gray-50 disabled:opacity-40; }
</style>
