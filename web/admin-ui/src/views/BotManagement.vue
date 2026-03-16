<template>
  <Layout>
    <div class="p-6">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('botManagement.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('botManagement.subtitle') }}</p>
        </div>
        <button @click="showAddModal = true" class="btn-primary">{{ $t('botManagement.addPattern') }}</button>
      </div>

      <!-- Test UA banner -->
      <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
        <div class="font-medium text-blue-800 text-sm mb-2">{{ $t('botManagement.testUA') }}</div>
        <div class="flex gap-2">
          <input
            v-model="testUA"
            type="text"
            class="input flex-1"
            placeholder="Mozilla/5.0 ..."
          />
          <button @click="testUserAgent" class="btn-primary">{{ $t('common.test') }}</button>
        </div>
        <div v-if="testResult !== null" class="mt-3 space-y-1">
          <div v-if="testResult.length === 0" class="text-sm text-green-700 font-medium">
            {{ $t('botManagement.noMatch') }}
          </div>
          <div v-for="match in testResult" :key="match.id" class="text-sm flex items-start gap-2">
            <span :class="match.action === 'block' ? 'text-red-600' : 'text-yellow-600'" class="font-semibold">
              {{ match.action.toUpperCase() }}
            </span>
            <span class="text-gray-800">{{ match.id }}: {{ match.name }}</span>
          </div>
        </div>
      </div>

      <!-- Category tabs -->
      <div class="flex gap-1 mb-4 border-b border-gray-200">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          @click="activeTab = tab.key"
          :class="activeTab === tab.key ? 'border-b-2 border-blue-600 text-blue-600' : 'text-gray-500 hover:text-gray-700'"
          class="px-4 py-2 text-sm font-medium"
        >
          {{ $t(tab.i18nKey) }}
          <span class="ml-1 text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded-full">
            {{ patternsByTab(tab.key).length }}
          </span>
        </button>
      </div>

      <!-- Pattern table -->
      <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.id') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.name') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.pattern') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.action') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.tags') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.status') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-if="patternsByTab(activeTab).length === 0">
              <td colspan="6" class="px-4 py-8 text-center text-gray-400 text-sm">{{ $t('botManagement.noPatterns') }}</td>
            </tr>
            <tr v-for="p in patternsByTab(activeTab)" :key="p.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 font-mono text-xs text-gray-500">{{ p.id }}</td>
              <td class="px-4 py-3 text-sm font-medium text-gray-900">{{ p.name }}</td>
              <td class="px-4 py-3 font-mono text-xs text-gray-600 max-w-xs truncate">{{ p.pattern }}</td>
              <td class="px-4 py-3">
                <span :class="actionClass(p.action)" class="px-2 py-0.5 rounded text-xs font-medium">{{ p.action }}</span>
              </td>
              <td class="px-4 py-3 text-xs text-gray-500">{{ p.tags?.join(', ') }}</td>
              <td class="px-4 py-3">
                <button @click="togglePattern(p)" class="text-xs" :class="p.enabled ? 'text-green-600' : 'text-gray-400'">
                  {{ p.enabled ? $t('botManagement.enabled') : $t('botManagement.disabled') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Add pattern modal -->
      <div v-if="showAddModal" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="showAddModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4">
          <div class="px-6 py-4 border-b">
            <h3 class="font-semibold text-gray-900">{{ $t('botManagement.addPatternTitle') }}</h3>
          </div>
          <div class="px-6 py-4 space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.patternRegex') }}</label>
              <input v-model="newPattern.pattern" type="text" class="input w-full font-mono" placeholder="(?i)\bMyBot\b" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.nameRequired') }}</label>
              <input v-model="newPattern.name" type="text" class="input w-full" :placeholder="$t('common.name')" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.actionField') }}</label>
              <select v-model="newPattern.action" class="input w-full">
                <option value="block">{{ $t('botManagement.block') }}</option>
                <option value="log">{{ $t('botManagement.logOnly') }}</option>
                <option value="allow">{{ $t('botManagement.allowWhitelist') }}</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.description') }}</label>
              <input v-model="newPattern.description" type="text" class="input w-full" :placeholder="$t('common.description')" />
            </div>
          </div>
          <div class="px-6 py-4 border-t flex gap-2 justify-end">
            <button @click="showAddModal = false" class="btn-secondary">{{ $t('common.cancel') }}</button>
            <button @click="addPattern" :disabled="!newPattern.pattern || !newPattern.name" class="btn-primary">{{ $t('botManagement.confirmAdd') }}</button>
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

useI18n()

interface BotPattern {
  id: string
  name: string
  pattern: string
  action: string
  tags?: string[]
  enabled: boolean
  source?: string
}

interface TestMatch {
  id: string
  name: string
  action: string
}

const patterns = ref<BotPattern[]>([])
const testUA = ref('')
const testResult = ref<TestMatch[] | null>(null)
const showAddModal = ref(false)
const activeTab = ref('bad')

const tabs = [
  { key: 'good', i18nKey: 'botManagement.goodBots' },
  { key: 'bad', i18nKey: 'botManagement.badBots' },
  { key: 'ai', i18nKey: 'botManagement.aiCrawlers' },
  { key: 'seo', i18nKey: 'botManagement.seoTools' },
  { key: 'custom', i18nKey: 'botManagement.custom' },
]

const newPattern = ref({ pattern: '', name: '', action: 'block', description: '' })

function patternsByTab(tab: string): BotPattern[] {
  const tagMap: Record<string, string> = {
    good: 'good-bot',
    bad: 'scraper',
    ai: 'ai-crawler',
    seo: 'seo-tool',
    custom: 'custom',
  }
  const tag = tagMap[tab]
  if (tab === 'custom') {
    return patterns.value.filter(p => p.source === 'custom')
  }
  return patterns.value.filter(p => p.tags?.includes(tag))
}

function actionClass(action: string) {
  return {
    block: 'bg-red-100 text-red-700',
    log: 'bg-yellow-100 text-yellow-700',
    allow: 'bg-green-100 text-green-700',
  }[action] ?? 'bg-gray-100 text-gray-600'
}

async function loadPatterns() {
  try {
    const { data } = await axios.get('/api/bot-patterns')
    patterns.value = data.patterns ?? []
  } catch {
    // Demo data
    patterns.value = [
      { id: 'BOT-GOOD-001', name: 'Googlebot', pattern: '(?i)\\bgooglebot\\b', action: 'allow', tags: ['good-bot', 'search-engine'], enabled: true },
      { id: 'BOT-BAD-001', name: 'Scrapy web scraper', pattern: '(?i)\\bscrapy\\b', action: 'block', tags: ['scraper'], enabled: true },
      { id: 'BOT-AI-001', name: 'OpenAI GPTBot', pattern: '(?i)\\bgptbot\\b', action: 'block', tags: ['ai-crawler', 'openai'], enabled: true },
      { id: 'BOT-AI-003', name: 'Claude-Web (Anthropic)', pattern: '(?i)\\bclaude-web\\b', action: 'block', tags: ['ai-crawler', 'anthropic'], enabled: true },
      { id: 'BOT-SEO-001', name: 'Semrush Bot', pattern: '(?i)\\bsemrushbot\\b', action: 'log', tags: ['seo-tool'], enabled: true },
    ]
  }
}

function testUserAgent() {
  const matches: TestMatch[] = []
  for (const p of patterns.value) {
    try {
      const re = new RegExp(p.pattern)
      if (re.test(testUA.value)) {
        matches.push({ id: p.id, name: p.name, action: p.action })
      }
    } catch { /* invalid regex */ }
  }
  testResult.value = matches
}

async function togglePattern(p: BotPattern) {
  const newState = !p.enabled
  try {
    await axios.patch(`/api/bot-patterns/${p.id}`, { enabled: newState })
    p.enabled = newState
  } catch {
    p.enabled = newState
  }
}

async function addPattern() {
  try {
    await axios.post('/api/bot-patterns', {
      pattern: newPattern.value.pattern,
      name: newPattern.value.name,
      action: newPattern.value.action,
      description: newPattern.value.description,
    })
    showAddModal.value = false
    newPattern.value = { pattern: '', name: '', action: 'block', description: '' }
    await loadPatterns()
  } catch (e) {
    console.error('Add failed', e)
  }
}

onMounted(loadPatterns)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50; }
</style>
