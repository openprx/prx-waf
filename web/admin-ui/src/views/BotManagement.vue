<!--
  Bot detection — the compiled-in catalogue plus the operator patterns stored in
  `bot_patterns`.

  Both halves come from `GET /api/bot-patterns`, which reads the engine's own
  `&'static` catalogue and the table its reload consults, so what is listed here
  is what the request path matches. Adding, editing or deleting an operator
  pattern republishes the engine's snapshot immediately — no restart.

  The operator layer is additive: it adds signatures and it can whitelist a
  User-Agent the built-ins would block, but it cannot switch a built-in off.

  Nothing here falls back to sample data. A failed call shows the server's own
  message, because "the list is empty" and "the list could not be fetched" are
  different facts about a firewall.
-->
<template>
  <Layout>
    <div class="p-6">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('botManagement.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('botManagement.subtitle') }}</p>
        </div>
        <button @click="openAdd" class="btn-primary">{{ $t('botManagement.addPattern') }}</button>
      </div>

      <div v-if="error" class="mb-4 text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">
        {{ error }}
      </div>

      <!-- Test UA banner. Evaluated by the engine, not by the browser: JS RegExp
           cannot parse the inline (?i) flag every shipped pattern begins with. -->
      <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
        <div class="font-medium text-blue-800 text-sm mb-2">{{ $t('botManagement.testUA') }}</div>
        <div class="flex gap-2">
          <input
            v-model="testUA"
            type="text"
            class="input flex-1"
            placeholder="Mozilla/5.0 ..."
            @keyup.enter="testUserAgent"
          />
          <button @click="testUserAgent" :disabled="!testUA || testing" class="btn-primary">
            {{ $t('common.test') }}
          </button>
        </div>
        <div v-if="testResult" class="mt-3 space-y-1">
          <div v-if="testResult.matches.length === 0" class="text-sm text-green-700 font-medium">
            {{ $t('botManagement.noMatch') }}
          </div>
          <template v-else>
            <div class="text-sm font-semibold" :class="testResult.verdict === 'allow' ? 'text-green-700' : 'text-red-700'">
              {{ testResult.verdict === 'allow' ? $t('botManagement.verdictAllow') : $t('botManagement.verdictBlock') }}
            </div>
            <div v-for="m in testResult.matches" :key="m.id" class="text-sm flex items-start gap-2">
              <span :class="m.action === 'block' ? 'text-red-600' : 'text-green-600'" class="font-semibold">
                {{ m.action.toUpperCase() }}
              </span>
              <span class="text-gray-800">{{ m.id }}: {{ m.name }}</span>
              <span class="text-xs text-gray-400">{{ m.source === 'builtin' ? $t('botManagement.builtin') : $t('botManagement.operator') }}</span>
            </div>
          </template>
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

      <p v-if="activeTab === 'user'" class="text-xs text-gray-500 mb-3">
        {{ $t('botManagement.userHint', { active: activeUserPatterns, max: limits.max_user_patterns }) }}
      </p>
      <p v-else class="text-xs text-gray-500 mb-3">{{ $t('botManagement.builtinHint') }}</p>

      <!-- Pattern table -->
      <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.id') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.name') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.pattern') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.action') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('botManagement.status') }}</th>
                <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">{{ $t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              <tr v-if="patternsByTab(activeTab).length === 0">
                <td colspan="6" class="px-4 py-8 text-center text-gray-400 text-sm">{{ $t('botManagement.noPatterns') }}</td>
              </tr>
              <tr v-for="p in patternsByTab(activeTab)" :key="`${p.source}-${p.id}`" class="hover:bg-gray-50">
                <td class="px-4 py-3 font-mono text-xs text-gray-500">{{ p.rule_id ?? p.id }}</td>
                <td class="px-4 py-3 text-sm font-medium text-gray-900">
                  {{ p.name }}
                  <div v-if="p.description" class="text-xs text-gray-400 font-normal">{{ p.description }}</div>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-gray-600 max-w-xs truncate" :title="p.pattern">{{ p.pattern }}</td>
                <td class="px-4 py-3">
                  <span :class="actionClass(p.action)" class="px-2 py-0.5 rounded text-xs font-medium">{{ p.action }}</span>
                </td>
                <td class="px-4 py-3">
                  <button
                    v-if="p.source === 'user'"
                    @click="toggleEnabled(p)"
                    class="text-xs"
                    :class="p.enabled ? 'text-green-600' : 'text-gray-400'"
                  >
                    {{ p.enabled ? $t('botManagement.enabled') : $t('botManagement.disabled') }}
                  </button>
                  <span v-else class="text-xs text-gray-400">{{ $t('botManagement.enabled') }}</span>
                </td>
                <td class="px-4 py-3 text-right whitespace-nowrap">
                  <template v-if="p.source === 'user'">
                    <button @click="openEdit(p)" class="text-xs text-blue-600 hover:underline mr-3">{{ $t('common.edit') }}</button>
                    <button @click="removePattern(p)" class="text-xs text-red-600 hover:underline">{{ $t('common.delete') }}</button>
                  </template>
                  <span v-else class="text-xs text-gray-300">{{ $t('botManagement.readOnly') }}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Add / edit modal -->
      <div v-if="showModal" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="showModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4">
          <div class="px-6 py-4 border-b">
            <h3 class="font-semibold text-gray-900">
              {{ editingId === null ? $t('botManagement.addPatternTitle') : $t('botManagement.editPatternTitle') }}
            </h3>
          </div>
          <div class="px-6 py-4 space-y-4">
            <div v-if="formError" class="text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">
              {{ formError }}
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.patternRegex') }}</label>
              <input v-model="form.pattern" type="text" class="input w-full font-mono" placeholder="(?i)\bMyBot\b" :maxlength="limits.max_pattern_len" />
              <p class="text-xs text-gray-400 mt-1">{{ $t('botManagement.patternHint') }}</p>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.nameRequired') }}</label>
              <input v-model="form.name" type="text" class="input w-full" :placeholder="$t('common.name')" :maxlength="limits.max_name_len" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.actionField') }}</label>
              <select v-model="form.action" class="input w-full">
                <option value="block">{{ $t('botManagement.block') }}</option>
                <option value="allow">{{ $t('botManagement.allowWhitelist') }}</option>
              </select>
              <p class="text-xs text-gray-400 mt-1">{{ $t('botManagement.actionHint') }}</p>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('botManagement.description') }}</label>
              <input v-model="form.description" type="text" class="input w-full" :placeholder="$t('common.description')" />
            </div>
          </div>
          <div class="px-6 py-4 border-t flex gap-2 justify-end">
            <button @click="showModal = false" class="btn-secondary">{{ $t('common.cancel') }}</button>
            <button @click="submit" :disabled="!form.pattern || !form.name || saving" class="btn-primary">
              {{ editingId === null ? $t('botManagement.confirmAdd') : $t('common.save') }}
            </button>
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
import { botPatternsApi, type BotPattern, type BotPatternLimits, type BotTestResult } from '../api'

const { t } = useI18n()

const DEFAULT_LIMITS: BotPatternLimits = { max_user_patterns: 512, max_pattern_len: 500, max_name_len: 100 }

const builtin = ref<BotPattern[]>([])
const userPatterns = ref<BotPattern[]>([])
const activeUserPatterns = ref(0)
const limits = ref<BotPatternLimits>(DEFAULT_LIMITS)
const error = ref('')

const testUA = ref('')
const testResult = ref<BotTestResult | null>(null)
const testing = ref(false)

const showModal = ref(false)
const editingId = ref<number | null>(null)
const saving = ref(false)
const formError = ref('')
const form = ref({ pattern: '', name: '', action: 'block', description: '' })

const activeTab = ref('user')
const tabs = [
  { key: 'user', i18nKey: 'botManagement.operatorPatterns' },
  { key: 'good', i18nKey: 'botManagement.goodBots' },
  { key: 'bad', i18nKey: 'botManagement.badBots' },
]

/** Turn an axios failure into the server's own message where there is one. */
function apiMessage(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
  return detail ? detail : fallback
}

function patternsByTab(tab: string): BotPattern[] {
  if (tab === 'user') return userPatterns.value
  return builtin.value.filter((p) => p.category === tab)
}

function actionClass(action: string) {
  return {
    block: 'bg-red-100 text-red-700',
    allow: 'bg-green-100 text-green-700',
  }[action] ?? 'bg-gray-100 text-gray-600'
}

async function loadPatterns() {
  error.value = ''
  try {
    const { data } = await botPatternsApi.list()
    builtin.value = data.data.builtin ?? []
    userPatterns.value = data.data.user ?? []
    activeUserPatterns.value = data.data.active_user_patterns ?? 0
    limits.value = data.data.limits ?? DEFAULT_LIMITS
  } catch (e) {
    builtin.value = []
    userPatterns.value = []
    error.value = apiMessage(e, t('botManagement.loadFailed'))
  }
}

async function testUserAgent() {
  testing.value = true
  error.value = ''
  try {
    const { data } = await botPatternsApi.test(testUA.value)
    testResult.value = data.data
  } catch (e) {
    testResult.value = null
    error.value = apiMessage(e, t('botManagement.testFailed'))
  } finally {
    testing.value = false
  }
}

function openAdd() {
  editingId.value = null
  formError.value = ''
  form.value = { pattern: '', name: '', action: 'block', description: '' }
  showModal.value = true
}

function openEdit(p: BotPattern) {
  editingId.value = Number(p.id)
  formError.value = ''
  form.value = { pattern: p.pattern, name: p.name, action: p.action, description: p.description ?? '' }
  showModal.value = true
}

async function submit() {
  saving.value = true
  formError.value = ''
  try {
    const payload = {
      name: form.value.name,
      pattern: form.value.pattern,
      action: form.value.action,
      description: form.value.description || undefined,
    }
    if (editingId.value === null) {
      await botPatternsApi.create(payload)
    } else {
      await botPatternsApi.update(editingId.value, payload)
    }
    showModal.value = false
    await loadPatterns()
  } catch (e) {
    // A rejected regex, an unsupported action or a full pattern set all arrive
    // here with a message written for the operator; show it verbatim.
    formError.value = apiMessage(e, t('botManagement.saveFailed'))
  } finally {
    saving.value = false
  }
}

async function toggleEnabled(p: BotPattern) {
  error.value = ''
  try {
    await botPatternsApi.update(Number(p.id), { enabled: !p.enabled })
    await loadPatterns()
  } catch (e) {
    error.value = apiMessage(e, t('botManagement.saveFailed'))
  }
}

async function removePattern(p: BotPattern) {
  error.value = ''
  if (!window.confirm(t('botManagement.confirmDelete', { name: p.name }))) return
  try {
    await botPatternsApi.delete(Number(p.id))
    await loadPatterns()
  } catch (e) {
    error.value = apiMessage(e, t('botManagement.deleteFailed'))
  }
}

onMounted(loadPatterns)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50; }
</style>
