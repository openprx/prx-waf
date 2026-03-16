<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold text-gray-800">CrowdSec Decisions</h2>
        <div class="flex gap-3 items-center">
          <span class="text-sm text-gray-500">{{ total }} active decisions</span>
          <button
            @click="load"
            class="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Refresh
          </button>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-white rounded-lg shadow p-4 mb-4 flex gap-4 flex-wrap">
        <input
          v-model="filter.value"
          placeholder="Filter by IP / value"
          class="border border-gray-300 rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"
        />
        <input
          v-model="filter.type"
          placeholder="Filter by type (ban, captcha...)"
          class="border border-gray-300 rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"
        />
        <input
          v-model="filter.scenario"
          placeholder="Filter by scenario"
          class="border border-gray-300 rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <!-- Table -->
      <div class="bg-white rounded-lg shadow overflow-hidden">
        <div v-if="loading" class="p-8 text-center text-gray-500">Loading decisions...</div>
        <div v-else-if="filteredDecisions.length === 0" class="p-8 text-center text-gray-500">
          No active decisions found.
          <span v-if="!isEnabled" class="block mt-1 text-sm">
            Enable CrowdSec integration in <router-link to="/crowdsec-settings" class="text-blue-600 underline">Settings</router-link>.
          </span>
        </div>
        <table v-else class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Value</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scenario</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Origin</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
            <tr v-for="d in filteredDecisions" :key="d.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 font-mono text-sm text-gray-900">{{ d.value }}</td>
              <td class="px-4 py-3">
                <span
                  :class="{
                    'bg-red-100 text-red-700': d.type_ === 'ban',
                    'bg-yellow-100 text-yellow-700': d.type_ === 'captcha',
                    'bg-orange-100 text-orange-700': d.type_ === 'throttle',
                    'bg-gray-100 text-gray-700': !['ban','captcha','throttle'].includes(d.type_),
                  }"
                  class="px-2 py-0.5 rounded text-xs font-medium"
                >{{ d.type_ }}</span>
              </td>
              <td class="px-4 py-3 text-sm text-gray-700 max-w-xs truncate" :title="d.scenario">{{ d.scenario }}</td>
              <td class="px-4 py-3 text-sm text-gray-600">{{ d.origin }}</td>
              <td class="px-4 py-3 text-sm text-gray-600">{{ d.scope }}</td>
              <td class="px-4 py-3 text-sm text-gray-600">{{ d.duration ?? '-' }}</td>
              <td class="px-4 py-3">
                <button
                  @click="deleteDecision(d.id)"
                  class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200"
                  title="Delete this decision via LAPI"
                >
                  Delete
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Error banner -->
      <div v-if="error" class="mt-3 p-3 bg-red-50 text-red-800 rounded">{{ error }}</div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import Layout from '../components/Layout.vue'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()

interface Decision {
  id: number
  origin: string
  scope: string
  value: string
  type_: string
  scenario: string
  duration?: string
}

const decisions = ref<Decision[]>([])
const total = ref(0)
const loading = ref(false)
const error = ref('')
const isEnabled = ref(false)

const filter = ref({ value: '', type: '', scenario: '' })

let refreshTimer: ReturnType<typeof setInterval> | null = null

function headers() {
  return { Authorization: `Bearer ${auth.token}` }
}

const filteredDecisions = computed(() => {
  return decisions.value.filter(d => {
    if (filter.value.value && !d.value.includes(filter.value.value)) return false
    if (filter.value.type && !d.type_.includes(filter.value.type)) return false
    if (filter.value.scenario && !d.scenario.includes(filter.value.scenario)) return false
    return true
  })
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [decResp, statusResp] = await Promise.all([
      axios.get('/api/crowdsec/decisions', { headers: headers() }),
      axios.get('/api/crowdsec/status', { headers: headers() }),
    ])
    decisions.value = decResp.data.decisions ?? []
    total.value = decResp.data.total ?? 0
    isEnabled.value = statusResp.data.enabled ?? false
  } catch (e: any) {
    error.value = e.response?.data?.error ?? e.message
  } finally {
    loading.value = false
  }
}

async function deleteDecision(id: number) {
  if (!confirm(`Delete decision ${id} from CrowdSec LAPI?`)) return
  error.value = ''
  try {
    await axios.delete(`/api/crowdsec/decisions/${id}`, { headers: headers() })
    await load()
  } catch (e: any) {
    error.value = e.response?.data?.error ?? e.message
  }
}

onMounted(() => {
  load()
  refreshTimer = setInterval(load, 10000) // auto-refresh every 10s
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>
