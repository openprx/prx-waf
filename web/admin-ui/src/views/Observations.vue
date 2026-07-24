<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-2">{{ $t('observations.title') }}</h2>

      <!-- Shadow-mode notice -->
      <div class="mb-5 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
        <EyeOff :size="18" class="mt-0.5 flex-shrink-0" />
        <span>{{ $t('observations.shadowNotice') }}</span>
      </div>

      <!-- Distribution summary -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
        <div class="bg-white rounded-xl shadow-sm p-4">
          <h3 class="text-sm font-medium text-gray-600 mb-3">{{ $t('observations.familyDistribution') }}</h3>
          <div v-if="families.length" class="space-y-2">
            <div v-for="f in families" :key="f.label" class="flex items-center gap-2">
              <span class="w-32 truncate text-xs font-mono text-gray-700">{{ f.label }}</span>
              <div class="flex-1 h-2 bg-gray-100 rounded overflow-hidden">
                <div class="h-full bg-indigo-400 rounded" :style="{ width: barWidth(f.count, maxFamily) }"></div>
              </div>
              <span class="w-10 text-right text-xs text-gray-500">{{ f.count }}</span>
            </div>
          </div>
          <p v-else class="text-xs text-gray-400">{{ $t('common.noData') }}</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm p-4">
          <h3 class="text-sm font-medium text-gray-600 mb-3">{{ $t('observations.recommendationDistribution') }}</h3>
          <div v-if="recommendations.length" class="flex flex-wrap gap-3">
            <div v-for="r in recommendations" :key="r.label" class="flex items-center gap-1.5">
              <span :class="recClass(r.label)" class="text-xs px-2 py-0.5 rounded font-medium">{{ r.label }}</span>
              <span class="text-sm font-semibold text-gray-700">{{ r.count }}</span>
            </div>
          </div>
          <p v-else class="text-xs text-gray-400">{{ $t('common.noData') }}</p>
        </div>
      </div>

      <!-- Filters -->
      <div class="flex gap-3 mb-4 flex-wrap">
        <input v-model.trim="filter.host_code" @keyup.enter="applyFilter" :placeholder="$t('observations.hostCode')" class="input text-sm w-36" />
        <input v-model.trim="filter.attack" @keyup.enter="applyFilter" :placeholder="$t('observations.attack')" class="input text-sm w-36" />
        <input v-model.trim="filter.rule_key" @keyup.enter="applyFilter" :placeholder="$t('observations.ruleKey')" class="input text-sm w-36" />
        <input v-model.number="filter.min_score" @keyup.enter="applyFilter" type="number" min="0" max="100" :placeholder="$t('observations.minScore')" class="input text-sm w-28" />
        <button @click="applyFilter" class="btn-primary text-sm">{{ $t('observations.filter') }}</button>
        <button @click="resetFilter" class="btn-secondary text-sm">{{ $t('observations.reset') }}</button>
        <button @click="reload" class="btn-secondary text-sm">{{ $t('common.refresh') }}</button>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="w-8 px-2 py-3"></th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.time') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.host') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.clientIP') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.scope') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.attack') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.score') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('observations.recommendation') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <template v-for="o in rows" :key="o.id">
              <tr class="hover:bg-gray-50 cursor-pointer" @click="toggle(o.id)">
                <td class="px-2 py-3 text-gray-400 text-center">
                  <ChevronRight :size="14" :class="{ 'rotate-90': expanded.has(o.id) }" class="transition-transform inline" />
                </td>
                <td class="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">{{ fmtTime(o.created_at) }}</td>
                <td class="px-4 py-3 font-mono text-xs">{{ o.host_code }}</td>
                <td class="px-4 py-3 font-mono text-xs">{{ o.client_ip }}</td>
                <td class="px-4 py-3 text-gray-600">{{ o.scope }}</td>
                <td class="px-4 py-3">
                  <span v-for="fam in families2(o)" :key="fam" class="mr-1 inline-block bg-indigo-50 text-indigo-700 text-xs px-1.5 py-0.5 rounded font-mono">{{ fam }}</span>
                  <span v-if="!families2(o).length" class="text-gray-300 text-xs">—</span>
                </td>
                <td class="px-4 py-3">
                  <span :class="scoreClass(o.request_score)" class="text-xs px-2 py-0.5 rounded font-semibold">{{ o.request_score }}</span>
                </td>
                <td class="px-4 py-3">
                  <span :class="recClass(o.recommendation)" class="text-xs px-2 py-0.5 rounded font-medium">{{ o.recommendation }}</span>
                  <span v-if="o.degraded" class="ml-1 text-xs px-1.5 py-0.5 rounded bg-orange-100 text-orange-700">{{ $t('observations.degraded') }}</span>
                  <span v-if="o.exhausted" class="ml-1 text-xs px-1.5 py-0.5 rounded bg-orange-100 text-orange-700">{{ $t('observations.exhausted') }}</span>
                </td>
              </tr>
              <!-- Expanded signal breakdown -->
              <tr v-if="expanded.has(o.id)" class="bg-gray-50">
                <td></td>
                <td colspan="7" class="px-4 py-3">
                  <div class="text-xs text-gray-500 mb-2 font-mono">{{ $t('observations.reqId') }}: {{ o.req_id }} · schema v{{ o.schema_version }} · {{ o.pipeline }}</div>
                  <table v-if="o.signals.length" class="w-full text-xs border border-gray-200 rounded">
                    <thead class="bg-gray-100">
                      <tr>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.detector') }}</th>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.attack') }}</th>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.field') }}</th>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.scope') }}</th>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.ruleKey') }}</th>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.provenance') }}</th>
                        <th class="text-left px-3 py-2 font-medium text-gray-500">{{ $t('observations.confidence') }}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(s, i) in o.signals" :key="i" class="border-t border-gray-100">
                        <td class="px-3 py-1.5 font-mono">{{ s.detector ?? '—' }}</td>
                        <td class="px-3 py-1.5 font-mono">{{ s.attack ?? '—' }}</td>
                        <td class="px-3 py-1.5 font-mono text-gray-500">{{ s.field ?? '—' }}</td>
                        <td class="px-3 py-1.5">{{ s.scope ?? '—' }}</td>
                        <td class="px-3 py-1.5 font-mono">{{ s.rule_key ?? '—' }}</td>
                        <td class="px-3 py-1.5">{{ s.provenance ?? '—' }}</td>
                        <td class="px-3 py-1.5">{{ s.confidence ?? '—' }}</td>
                      </tr>
                    </tbody>
                  </table>
                  <p v-else class="text-xs text-gray-400">{{ $t('observations.noRows') }}</p>
                </td>
              </tr>
            </template>
            <tr v-if="!rows.length">
              <td colspan="8" class="px-4 py-8 text-center text-gray-400">{{ $t('observations.empty') }}</td>
            </tr>
          </tbody>
        </table>
        <!-- Pagination -->
        <div class="px-4 py-3 border-t flex items-center justify-between text-sm text-gray-500">
          <span>{{ $t('common.total') }}: {{ total }}</span>
          <div class="flex gap-2 items-center">
            <button @click="prevPage" :disabled="page <= 1" class="btn-secondary text-xs">{{ $t('common.prev') }}</button>
            <span>{{ page }}</span>
            <button @click="nextPage" :disabled="page * pageSize >= total" class="btn-secondary text-xs">{{ $t('common.next') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ChevronRight, EyeOff } from 'lucide-vue-next'
import { observationsApi, type Observation, type LabeledCount, type ObservationFilters } from '../api'
import Layout from '../components/Layout.vue'

const rows = ref<Observation[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 50
const expanded = ref<Set<string>>(new Set())

const families = ref<LabeledCount[]>([])
const recommendations = ref<LabeledCount[]>([])
const maxFamily = computed(() => families.value.reduce((m, f) => Math.max(m, f.count), 0))

const filter = ref<ObservationFilters>({ host_code: '', attack: '', rule_key: '', min_score: undefined })

function cleanFilters(): ObservationFilters {
  const f = filter.value
  const out: ObservationFilters = { page: page.value, page_size: pageSize }
  if (f.host_code) out.host_code = f.host_code
  if (f.attack) out.attack = f.attack
  if (f.rule_key) out.rule_key = f.rule_key
  if (typeof f.min_score === 'number' && !Number.isNaN(f.min_score)) out.min_score = f.min_score
  return out
}

async function load() {
  const r = await observationsApi.list(cleanFilters())
  rows.value = r.data.data
  total.value = r.data.total
}

async function loadStats() {
  const r = await observationsApi.stats(24)
  families.value = r.data.data.families
  recommendations.value = r.data.data.recommendations
}

function reload() {
  load()
  loadStats()
}

function applyFilter() {
  page.value = 1
  load()
}

function resetFilter() {
  filter.value = { host_code: '', attack: '', rule_key: '', min_score: undefined }
  page.value = 1
  load()
}

function prevPage() {
  if (page.value > 1) {
    page.value--
    load()
  }
}

function nextPage() {
  if (page.value * pageSize < total.value) {
    page.value++
    load()
  }
}

function toggle(id: string) {
  const next = new Set(expanded.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expanded.value = next
}

function families2(o: Observation): string[] {
  const set = new Set<string>()
  for (const s of o.signals) {
    if (s.attack) set.add(s.attack)
  }
  return [...set]
}

function barWidth(count: number, max: number): string {
  if (max <= 0) return '0%'
  return `${Math.max(4, Math.round((count / max) * 100))}%`
}

function scoreClass(score: number): string {
  if (score >= 60) return 'bg-red-100 text-red-700'
  if (score >= 30) return 'bg-amber-100 text-amber-700'
  return 'bg-gray-100 text-gray-600'
}

function recClass(rec: string): string {
  if (rec === 'block') return 'bg-red-100 text-red-700'
  if (rec === 'log') return 'bg-amber-100 text-amber-700'
  return 'bg-gray-100 text-gray-600'
}

function fmtTime(ts: string): string {
  return new Date(ts).toLocaleString()
}

onMounted(reload)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 disabled:opacity-50; }
</style>
