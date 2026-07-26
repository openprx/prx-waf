<!--
  OWASP CRS rule registry and the per-rule override layer.

  Read from `GET /api/rules/registry`, which is the live `waf_engine::OWASPCheck`
  for the queried scope — a rule missing here is a rule genuinely not enforced.
  Overrides (`/api/rules/overrides`) are strictly subtractive: they can disable a
  rule or downgrade it to log-only, never add one or escalate to an unconditional
  deny. Nothing on this page falls back to sample data — a failed call shows the
  server's own message, and no control here calls an endpoint that does not
  exist (there is no rule import).
-->
<template>
  <Layout>
    <div class="p-6">
      <div class="mb-6 flex items-start justify-between gap-4">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('rules.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('rules.manageRules') }}</p>
        </div>
        <div class="flex items-center gap-3">
          <label class="text-sm text-gray-600">{{ $t('rules.scopeLabel') }}</label>
          <select v-model="selectedHostCode" class="input w-56">
            <option value="">{{ $t('rules.scopeGlobal') }}</option>
            <option v-for="h in hosts" :key="h.id" :value="h.code">{{ h.host }} ({{ h.code }})</option>
          </select>
          <button @click="doReload" :disabled="loading" class="btn-secondary">{{ $t('rules.reloadRules') }}</button>
        </div>
      </div>

      <p class="text-xs text-gray-500 mb-4">{{ $t('rules.scopeHint') }}</p>

      <div v-if="error" class="mb-4 text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">
        {{ error }}
      </div>

      <div v-if="lastWarning" class="mb-4 flex items-start justify-between gap-2 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded px-3 py-2">
        <span>{{ lastWarning }}</span>
        <button @click="lastWarning = ''" class="text-amber-600 hover:text-amber-800 shrink-0"><X :size="14" /></button>
      </div>

      <div v-if="reloadResult" class="mb-4 flex items-start justify-between gap-2 text-sm text-blue-800 bg-blue-50 border border-blue-200 rounded px-3 py-2">
        <div>
          <div>
            {{ $t('rules.reloadResult', {
              applied: reloadResult.applied,
              disabled: reloadResult.disabled,
              logOnly: reloadResult.log_only,
              hosts: reloadResult.hosts,
              enforced: reloadResult.enforced_rules,
            }) }}
          </div>
          <div v-if="reloadResult.unknown_rule_ids.length" class="mt-1">
            {{ $t('rules.reloadUnknownIds', { ids: reloadResult.unknown_rule_ids.join(', ') }) }}
          </div>
        </div>
        <button @click="reloadResult = null" class="text-blue-600 hover:text-blue-800 shrink-0"><X :size="14" /></button>
      </div>

      <!-- Summary bar -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-gray-900">
            {{ summary?.enforced ?? 0 }}<span class="text-sm text-gray-400 font-normal"> / {{ summary?.declared ?? 0 }}</span>
          </div>
          <div class="text-sm text-gray-500">{{ $t('rules.enforced') }} / {{ $t('rules.totalRules') }}</div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-blue-600">{{ summary?.request_rules ?? 0 }}</div>
          <div class="text-sm text-gray-500">{{ $t('rules.requestRules') }}</div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold text-blue-600">{{ summary?.response_rules ?? 0 }}</div>
          <div class="text-sm text-gray-500">{{ $t('rules.responseRules') }}</div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold" :class="(summary?.disabled ?? 0) > 0 ? 'text-red-600' : 'text-gray-400'">
            {{ summary?.disabled ?? 0 }}
          </div>
          <div class="text-sm" :class="(summary?.disabled ?? 0) > 0 ? 'text-red-600 font-medium' : 'text-gray-500'">
            {{ $t('rules.disabledRules') }}
          </div>
        </div>
        <div class="bg-white rounded-lg p-4 border border-gray-200">
          <div class="text-2xl font-bold" :class="(summary?.log_only ?? 0) > 0 ? 'text-yellow-600' : 'text-gray-400'">
            {{ summary?.log_only ?? 0 }}
          </div>
          <div class="text-sm text-gray-500">{{ $t('rules.logOnly') }}</div>
        </div>
      </div>

      <!-- Degraded notice -->
      <div v-if="summary?.degraded" class="mb-4 flex items-start gap-2 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded px-3 py-2">
        <AlertTriangle :size="16" class="shrink-0 mt-0.5" />
        <div>
          <div class="font-medium">{{ $t('rules.degradedBanner', { rejected: summary.rejected }) }}</div>
          <div v-if="summary.used_embedded_fallback">{{ $t('rules.usedFallbackNotice') }}</div>
          <template v-if="summary.rejected_rules.length">
            <div class="mt-1 font-medium">{{ $t('rules.rejectedRulesLabel') }}:</div>
            <ul class="list-disc list-inside text-xs">
              <li v-for="r in summary.rejected_rules" :key="`${r.rule_id}-${r.source}`">
                {{ r.rule_id }} ({{ r.source }}): {{ r.reason }}
              </li>
            </ul>
          </template>
        </div>
      </div>

      <!-- Tabs -->
      <div class="flex gap-1 mb-4 border-b border-gray-200">
        <button
          @click="activeTab = 'rules'"
          :class="activeTab === 'rules' ? 'border-b-2 border-blue-600 text-blue-600' : 'text-gray-500 hover:text-gray-700'"
          class="px-4 py-2 text-sm font-medium"
        >{{ $t('rules.tabRules') }}</button>
        <button
          @click="activeTab = 'overrides'"
          :class="activeTab === 'overrides' ? 'border-b-2 border-blue-600 text-blue-600' : 'text-gray-500 hover:text-gray-700'"
          class="px-4 py-2 text-sm font-medium"
        >
          {{ $t('rules.tabOverrides') }}
          <span class="ml-1 text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded-full">{{ overrides.length }}</span>
        </button>
      </div>

      <template v-if="activeTab === 'rules'">
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
          <select v-model="filterPhase" class="input w-36">
            <option value="">{{ $t('rules.allPhases') }}</option>
            <option value="request">{{ $t('rules.phaseRequest') }}</option>
            <option value="response">{{ $t('rules.phaseResponse') }}</option>
          </select>
          <select v-model="filterState" class="input w-40">
            <option value="">{{ $t('rules.allStates') }}</option>
            <option value="active">{{ $t('rules.stateActive') }}</option>
            <option value="disabled">{{ $t('rules.stateDisabled') }}</option>
            <option value="log_only">{{ $t('rules.stateLogOnly') }}</option>
            <option value="overridden">{{ $t('rules.stateOverridden') }}</option>
          </select>
        </div>

        <!-- Rules table -->
        <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.ruleId') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('common.name') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.category') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.severity') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.paranoia') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.phase') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.declaredAction') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.effectiveAction') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('common.status') }}</th>
                  <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">{{ $t('common.actions') }}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100">
                <tr v-if="loading">
                  <td colspan="10" class="px-4 py-8 text-center text-gray-500">{{ $t('rules.loadingRules') }}</td>
                </tr>
                <tr v-else-if="filteredRules.length === 0">
                  <td colspan="10" class="px-4 py-8 text-center text-gray-400">{{ $t('rules.noRulesFound') }}</td>
                </tr>
                <tr v-for="rule in paginatedRules" :key="rule.id" class="hover:bg-gray-50">
                  <td class="px-4 py-3 font-mono text-xs text-gray-700">{{ rule.id }}</td>
                  <td class="px-4 py-3 text-sm text-gray-900">{{ rule.name }}</td>
                  <td class="px-4 py-3">
                    <span class="px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">{{ rule.category }}</span>
                  </td>
                  <td class="px-4 py-3">
                    <span :class="severityClass(rule.severity)" class="px-2 py-0.5 rounded text-xs font-medium">{{ rule.severity }}</span>
                  </td>
                  <td class="px-4 py-3 text-xs text-gray-600">{{ rule.paranoia }}</td>
                  <td class="px-4 py-3 text-xs text-gray-600">{{ phaseLabel(rule.phase) }}</td>
                  <td class="px-4 py-3">
                    <span :class="actionClass(rule.declared_action)" class="px-2 py-0.5 rounded text-xs font-medium">{{ rule.declared_action }}</span>
                  </td>
                  <td class="px-4 py-3">
                    <span :class="actionClass(rule.effective_action)" class="px-2 py-0.5 rounded text-xs font-medium">{{ rule.effective_action }}</span>
                  </td>
                  <td class="px-4 py-3">
                    <span :class="stateClass(rule.state)" class="px-2 py-0.5 rounded text-xs font-medium">{{ stateLabel(rule.state) }}</span>
                    <span v-if="rule.overridden" class="ml-1 px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-500">{{ $t('rules.stateOverridden') }}</span>
                  </td>
                  <td class="px-4 py-3 text-right whitespace-nowrap text-xs">
                    <button v-if="rule.state !== 'disabled'" @click="openDisableDialog(rule)" class="text-red-600 hover:underline mr-2">
                      {{ $t('rules.disable') }}
                    </button>
                    <button v-if="rule.state !== 'log_only'" @click="setLogOnly(rule)" class="text-yellow-700 hover:underline mr-2">
                      {{ $t('rules.setLogOnly') }}
                    </button>
                    <button v-if="rule.overridden" @click="restoreRule(rule)" class="text-blue-600 hover:underline">
                      {{ $t('rules.restore') }}
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Pagination -->
          <div class="px-4 py-3 border-t flex items-center justify-between text-sm text-gray-500">
            <span>{{ $t('rules.showing') }} {{ paginationStart }}–{{ paginationEnd }} {{ $t('rules.of') }} {{ filteredRules.length }} {{ $t('common.total').toLowerCase() }}</span>
            <div class="flex gap-1">
              <button @click="page--" :disabled="page <= 1" class="btn-page">{{ $t('common.prev') }}</button>
              <button @click="page++" :disabled="page >= pageCount" class="btn-page">{{ $t('common.next') }}</button>
            </div>
          </div>
        </div>
      </template>

      <template v-else>
        <!-- Overrides table -->
        <div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.ruleId') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.overrideScope') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('common.status') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.note') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.created') }}</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('rules.updated') }}</th>
                  <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">{{ $t('common.actions') }}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100">
                <tr v-if="overrides.length === 0">
                  <td colspan="7" class="px-4 py-8 text-center text-gray-400">{{ $t('rules.noOverrides') }}</td>
                </tr>
                <tr v-for="o in overrides" :key="o.id" class="hover:bg-gray-50">
                  <td class="px-4 py-3 font-mono text-xs text-gray-700">
                    {{ o.rule_id }}
                    <span
                      v-if="!o.known_rule"
                      :title="$t('rules.unknownRuleHint')"
                      class="ml-1 px-1.5 py-0.5 rounded text-xs bg-gray-200 text-gray-600"
                    >{{ $t('rules.unknownRuleBadge') }}</span>
                  </td>
                  <td class="px-4 py-3 text-xs text-gray-600">{{ o.host_code ?? $t('rules.scopeGlobal') }}</td>
                  <td class="px-4 py-3">
                    <span v-if="o.state !== 'invalid'" :class="stateClass(o.state)" class="px-2 py-0.5 rounded text-xs font-medium">{{ stateLabel(o.state) }}</span>
                    <span v-else class="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">{{ o.state }}</span>
                  </td>
                  <td class="px-4 py-3 text-xs text-gray-600 max-w-xs truncate" :title="o.note ?? ''">{{ o.note || '—' }}</td>
                  <td class="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">{{ o.created_at }}</td>
                  <td class="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">{{ o.updated_at }}</td>
                  <td class="px-4 py-3 text-right whitespace-nowrap text-xs">
                    <button @click="openEditNote(o)" class="text-blue-600 hover:underline mr-2">{{ $t('rules.editNote') }}</button>
                    <button @click="deleteOverrideRow(o)" class="text-red-600 hover:underline">{{ $t('common.delete') }}</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>

      <!-- Disable confirmation dialog -->
      <div v-if="disableTarget" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="closeDisableDialog">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4">
          <div class="px-6 py-4 border-b">
            <h3 class="font-semibold text-gray-900">{{ $t('rules.disableDialogTitle', { id: disableTarget.id }) }}</h3>
          </div>
          <div class="px-6 py-4 space-y-3 text-sm">
            <div v-if="disableError" class="text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{{ disableError }}</div>
            <p class="text-gray-700">{{ $t('rules.disableDialogBody') }}</p>
            <p class="text-gray-700 bg-blue-50 border border-blue-100 rounded px-3 py-2">{{ $t('rules.disableDialogAlternative') }}</p>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('rules.noteLabel') }}</label>
              <input v-model="disableNote" type="text" class="input w-full" :placeholder="$t('rules.notePlaceholder')" />
            </div>
          </div>
          <div class="px-6 py-4 border-t flex flex-wrap gap-2 justify-end">
            <button @click="closeDisableDialog" class="btn-secondary">{{ $t('common.cancel') }}</button>
            <button @click="useLogOnlyInstead" :disabled="disableSaving" class="btn-secondary">{{ $t('rules.useLogOnlyInstead') }}</button>
            <button @click="confirmDisable" :disabled="disableSaving" class="btn-danger">{{ $t('rules.confirmDisable') }}</button>
          </div>
        </div>
      </div>

      <!-- Edit note modal -->
      <div v-if="editingOverride" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50" @click.self="editingOverride = null">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4">
          <div class="px-6 py-4 border-b">
            <h3 class="font-semibold text-gray-900">{{ $t('rules.editNoteTitle', { id: editingOverride.rule_id }) }}</h3>
          </div>
          <div class="px-6 py-4 space-y-3">
            <div v-if="editNoteError" class="text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{{ editNoteError }}</div>
            <textarea v-model="editNoteDraft" class="input w-full" rows="3" :placeholder="$t('rules.notePlaceholder')"></textarea>
          </div>
          <div class="px-6 py-4 border-t flex gap-2 justify-end">
            <button @click="editingOverride = null" class="btn-secondary">{{ $t('common.cancel') }}</button>
            <button @click="saveEditNote" :disabled="editNoteSaving" class="btn-primary">{{ $t('common.save') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { X, AlertTriangle } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import {
  hostsApi,
  rulesApi,
  type RuleDescriptor,
  type RuleOverride,
  type RulesRegistry,
  type ReloadRulesReport,
} from '../api'

const { t } = useI18n()

interface HostSummary {
  id: string
  code: string
  host: string
}

const hosts = ref<HostSummary[]>([])
const selectedHostCode = ref('')

const registry = ref<RulesRegistry | null>(null)
const overrides = ref<RuleOverride[]>([])
const loading = ref(false)
const error = ref('')
const lastWarning = ref('')
const reloadResult = ref<ReloadRulesReport | null>(null)

const activeTab = ref<'rules' | 'overrides'>('rules')

const searchQuery = ref('')
const filterCategory = ref('')
const filterPhase = ref('')
const filterState = ref('')
const page = ref(1)
const pageSize = 20

const disableTarget = ref<RuleDescriptor | null>(null)
const disableNote = ref('')
const disableSaving = ref(false)
const disableError = ref('')

const editingOverride = ref<RuleOverride | null>(null)
const editNoteDraft = ref('')
const editNoteSaving = ref(false)
const editNoteError = ref('')

const rules = computed<RuleDescriptor[]>(() => registry.value?.rules ?? [])
const summary = computed(() => registry.value?.summary ?? null)
const categories = computed(() => [...new Set(rules.value.map((r) => r.category))].sort())

/** Turn an axios failure into the server's own message where there is one. */
function apiMessage(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
  return detail ? detail : fallback
}

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
    deny: 'bg-red-100 text-red-700',
    score: 'bg-blue-100 text-blue-700',
    log: 'bg-yellow-100 text-yellow-700',
    disabled: 'bg-gray-100 text-gray-500',
  }[action] ?? 'bg-gray-100 text-gray-600'
}

function stateClass(state: string) {
  return {
    active: 'bg-green-100 text-green-700',
    disabled: 'bg-red-100 text-red-700',
    log_only: 'bg-yellow-100 text-yellow-700',
  }[state] ?? 'bg-gray-100 text-gray-600'
}

function stateLabel(state: string) {
  return ({
    active: t('rules.stateActive'),
    disabled: t('rules.stateDisabled'),
    log_only: t('rules.stateLogOnly'),
  } as Record<string, string>)[state] ?? state
}

function phaseLabel(phase: string) {
  if (phase === 'request') return t('rules.phaseRequest')
  if (phase === 'response') return t('rules.phaseResponse')
  return phase
}

const filteredRules = computed(() => {
  let list = rules.value
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter((r) => r.id.toLowerCase().includes(q) || r.name.toLowerCase().includes(q))
  }
  if (filterCategory.value) list = list.filter((r) => r.category === filterCategory.value)
  if (filterPhase.value) list = list.filter((r) => r.phase === filterPhase.value)
  if (filterState.value === 'overridden') list = list.filter((r) => r.overridden)
  else if (filterState.value) list = list.filter((r) => r.state === filterState.value)
  return list
})

const pageCount = computed(() => Math.max(1, Math.ceil(filteredRules.value.length / pageSize)))
const paginatedRules = computed(() => filteredRules.value.slice((page.value - 1) * pageSize, page.value * pageSize))
const paginationStart = computed(() => Math.min((page.value - 1) * pageSize + 1, filteredRules.value.length))
const paginationEnd = computed(() => Math.min(page.value * pageSize, filteredRules.value.length))

/**
 * The override governing a rule in the current scope: a host-specific row
 * takes precedence, falling back to the global row — mirrors what the engine
 * itself resolves when it builds `rule.state`.
 */
function findOverrideFor(ruleId: string): RuleOverride | undefined {
  const hostCode = selectedHostCode.value || null
  return (
    overrides.value.find((o) => o.rule_id === ruleId && o.host_code === hostCode) ??
    (hostCode !== null ? overrides.value.find((o) => o.rule_id === ruleId && o.host_code === null) : undefined)
  )
}

async function loadHosts() {
  try {
    const { data } = await hostsApi.list()
    hosts.value = data.data ?? []
  } catch {
    hosts.value = []
  }
}

async function loadRegistry() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await rulesApi.registry(selectedHostCode.value || undefined)
    registry.value = data.data
  } catch (e) {
    registry.value = null
    error.value = apiMessage(e, t('rules.loadRegistryFailed'))
  } finally {
    loading.value = false
  }
}

async function loadOverrides() {
  try {
    const { data } = await rulesApi.overrides()
    overrides.value = data.data.overrides ?? []
  } catch (e) {
    overrides.value = []
    error.value = apiMessage(e, t('rules.loadOverridesFailed'))
  }
}

async function loadAll() {
  await Promise.all([loadRegistry(), loadOverrides()])
}

watch(selectedHostCode, () => {
  page.value = 1
  loadRegistry()
})

function openDisableDialog(rule: RuleDescriptor) {
  disableTarget.value = rule
  disableNote.value = ''
  disableError.value = ''
}

function closeDisableDialog() {
  disableTarget.value = null
}

async function confirmDisable() {
  if (!disableTarget.value) return
  disableSaving.value = true
  disableError.value = ''
  try {
    const { data } = await rulesApi.createOverride({
      rule_id: disableTarget.value.id,
      host_code: selectedHostCode.value || null,
      enabled: false,
      note: disableNote.value || undefined,
    })
    lastWarning.value = data.warning ?? ''
    disableTarget.value = null
    await loadAll()
  } catch (e) {
    disableError.value = apiMessage(e, t('rules.saveOverrideFailed'))
  } finally {
    disableSaving.value = false
  }
}

async function useLogOnlyInstead() {
  if (!disableTarget.value) return
  disableSaving.value = true
  disableError.value = ''
  try {
    const { data } = await rulesApi.createOverride({
      rule_id: disableTarget.value.id,
      host_code: selectedHostCode.value || null,
      action_override: 'log',
      note: disableNote.value || undefined,
    })
    lastWarning.value = data.warning ?? ''
    disableTarget.value = null
    await loadAll()
  } catch (e) {
    disableError.value = apiMessage(e, t('rules.saveOverrideFailed'))
  } finally {
    disableSaving.value = false
  }
}

async function setLogOnly(rule: RuleDescriptor) {
  if (!window.confirm(t('rules.logOnlyConfirm', { id: rule.id }))) return
  error.value = ''
  try {
    const { data } = await rulesApi.createOverride({
      rule_id: rule.id,
      host_code: selectedHostCode.value || null,
      action_override: 'log',
    })
    lastWarning.value = data.warning ?? ''
    await loadAll()
  } catch (e) {
    error.value = apiMessage(e, t('rules.saveOverrideFailed'))
  }
}

async function restoreRule(rule: RuleDescriptor) {
  const ov = findOverrideFor(rule.id)
  if (!ov) return
  if (!window.confirm(t('rules.restoreConfirm', { id: rule.id }))) return
  error.value = ''
  try {
    await rulesApi.deleteOverride(ov.id)
    await loadAll()
  } catch (e) {
    error.value = apiMessage(e, t('rules.deleteOverrideFailed'))
  }
}

async function deleteOverrideRow(row: RuleOverride) {
  if (!window.confirm(t('rules.restoreConfirm', { id: row.rule_id }))) return
  error.value = ''
  try {
    await rulesApi.deleteOverride(row.id)
    await loadAll()
  } catch (e) {
    error.value = apiMessage(e, t('rules.deleteOverrideFailed'))
  }
}

function openEditNote(row: RuleOverride) {
  editingOverride.value = row
  editNoteDraft.value = row.note ?? ''
  editNoteError.value = ''
}

async function saveEditNote() {
  if (!editingOverride.value) return
  editNoteSaving.value = true
  editNoteError.value = ''
  try {
    await rulesApi.updateOverride(editingOverride.value.id, {
      enabled: editingOverride.value.enabled,
      action_override: editingOverride.value.action_override,
      note: editNoteDraft.value || undefined,
    })
    editingOverride.value = null
    await loadAll()
  } catch (e) {
    editNoteError.value = apiMessage(e, t('rules.saveOverrideFailed'))
  } finally {
    editNoteSaving.value = false
  }
}

async function doReload() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await rulesApi.reload()
    reloadResult.value = data.data
    await loadAll()
  } catch (e) {
    error.value = apiMessage(e, t('rules.reloadFailed'))
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadHosts()
  loadAll()
})
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 disabled:opacity-50; }
.btn-danger { @apply bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-red-700 disabled:opacity-50; }
.btn-page { @apply px-3 py-1 border border-gray-300 rounded text-sm hover:bg-gray-50 disabled:opacity-40; }
</style>
