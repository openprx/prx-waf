<!--
  Admin action trail — the read side of the `audit_log` table.

  Every mutating admin API call is recorded by `waf_api::audit`, including the
  ones that were refused. This is the only history that survives the change it
  describes: a deleted block-ip rule leaves no other trace it ever existed.
-->
<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-1">{{ $t('auditLog.title') }}</h2>
      <p class="text-sm text-gray-500 mb-6">{{ $t('auditLog.subtitle') }}</p>

      <!-- Filters -->
      <div class="flex gap-3 mb-4 flex-wrap">
        <input
          v-model.trim="filter.admin_username"
          @keyup.enter="applyFilter"
          :placeholder="$t('auditLog.admin')"
          class="input text-sm w-40"
        />
        <input
          v-model.trim="filter.action"
          @keyup.enter="applyFilter"
          :placeholder="$t('auditLog.actionFilter')"
          class="input text-sm w-64"
        />
        <button @click="applyFilter" class="btn-primary text-sm">{{ $t('auditLog.filter') }}</button>
        <button @click="resetFilter" class="btn-secondary text-sm">{{ $t('auditLog.reset') }}</button>
      </div>

      <div v-if="error" class="mb-4 text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">
        {{ error }}
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-gray-50 border-b">
              <tr>
                <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('auditLog.time') }}</th>
                <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('auditLog.admin') }}</th>
                <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('auditLog.action') }}</th>
                <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('auditLog.resource') }}</th>
                <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('auditLog.outcome') }}</th>
                <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('auditLog.ip') }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              <tr v-for="e in entries" :key="e.id" class="hover:bg-gray-50">
                <td class="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">{{ fmtTime(e.created_at) }}</td>
                <td class="px-4 py-3 text-gray-800">{{ e.admin_username ?? '—' }}</td>
                <td class="px-4 py-3 font-mono text-xs text-gray-700">{{ e.action }}</td>
                <td class="px-4 py-3 text-xs text-gray-600">
                  <span>{{ e.resource_type ?? '—' }}</span>
                  <span v-if="e.resource_id" class="font-mono text-gray-400 ml-1">{{ e.resource_id }}</span>
                </td>
                <td class="px-4 py-3">
                  <span :class="outcomeClass(e)" class="text-xs px-2 py-0.5 rounded font-medium">
                    {{ outcomeLabel(e) }}
                  </span>
                  <span v-if="e.detail?.status" class="text-xs text-gray-400 ml-1">{{ e.detail.status }}</span>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-gray-500">{{ e.ip_addr ?? '—' }}</td>
              </tr>
              <tr v-if="!entries.length">
                <td colspan="6" class="px-4 py-6 text-center text-gray-400">{{ $t('auditLog.noEntries') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <!-- Pagination -->
        <div class="px-4 py-3 border-t flex items-center justify-between text-sm text-gray-500">
          <span>{{ $t('common.total') }}: {{ total }}</span>
          <div class="flex gap-2 items-center">
            <button @click="prevPage" :disabled="page <= 1" class="btn-secondary text-xs">{{ $t('common.prev') }}</button>
            <span>{{ page }}</span>
            <button @click="nextPage" :disabled="page * pageSize >= total" class="btn-secondary text-xs">
              {{ $t('common.next') }}
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
import { auditApi, type AuditLogEntry, type AuditLogFilters } from '../api'
import Layout from '../components/Layout.vue'

const { t } = useI18n()

const entries = ref<AuditLogEntry[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 20
const error = ref('')
const filter = ref<AuditLogFilters>({ admin_username: '', action: '' })

async function load() {
  error.value = ''
  try {
    const r = await auditApi.list({
      admin_username: filter.value.admin_username || undefined,
      action: filter.value.action || undefined,
      page: page.value,
      page_size: pageSize,
    })
    entries.value = r.data.entries ?? []
    total.value = r.data.total ?? 0
  } catch {
    entries.value = []
    total.value = 0
    error.value = t('auditLog.loadFailed')
  }
}

function applyFilter() {
  page.value = 1
  void load()
}

function resetFilter() {
  filter.value = { admin_username: '', action: '' }
  applyFilter()
}

function prevPage() {
  page.value -= 1
  void load()
}

function nextPage() {
  page.value += 1
  void load()
}

function outcomeLabel(e: AuditLogEntry): string {
  const outcome = e.detail?.outcome
  if (outcome === 'success') return t('auditLog.success')
  if (outcome === 'denied') return t('auditLog.denied')
  if (outcome === 'error') return t('auditLog.error')
  return t('auditLog.unknown')
}

function outcomeClass(e: AuditLogEntry): string {
  switch (e.detail?.outcome) {
    case 'success':
      return 'bg-green-100 text-green-700'
    case 'denied':
      return 'bg-yellow-100 text-yellow-700'
    case 'error':
      return 'bg-red-100 text-red-700'
    default:
      return 'bg-gray-100 text-gray-600'
  }
}

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString()
}

onMounted(load)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 disabled:opacity-50; }
</style>
