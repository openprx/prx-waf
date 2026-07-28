<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold text-gray-800">{{ $t('crowdsec.decisions.title') }}</h2>
        <div class="flex gap-3 items-center">
          <span class="text-sm text-gray-500">{{ total }} {{ $t('crowdsec.decisions.activeDecisions') }}</span>
          <button
            @click="load"
            class="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            {{ $t('common.refresh') }}
          </button>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-white rounded-lg shadow p-4 mb-4 flex gap-4 flex-wrap">
        <input
          v-model="filter.value"
          :placeholder="$t('crowdsec.decisions.filterByIp')"
          class="border border-gray-300 rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"
        />
        <input
          v-model="filter.type"
          :placeholder="$t('crowdsec.decisions.filterByType')"
          class="border border-gray-300 rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"
        />
        <input
          v-model="filter.scenario"
          :placeholder="$t('crowdsec.decisions.filterByScenario')"
          class="border border-gray-300 rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <!-- Table -->
      <div class="bg-white rounded-lg shadow overflow-hidden">
        <div v-if="loading" class="p-8 text-center text-gray-500">{{ $t('crowdsec.decisions.loading') }}</div>
        <div v-else-if="filteredDecisions.length === 0" class="p-8 text-center text-gray-500">
          {{ $t('crowdsec.decisions.noDecisions') }}
          <span v-if="!isEnabled" class="block mt-1 text-sm">
            {{ $t('crowdsec.decisions.enableCrowdsec') }} <router-link to="/crowdsec-settings" class="text-blue-600 underline">{{ $t('nav.settings') }}</router-link>.
          </span>
        </div>
        <table v-else class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.value') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.type') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.scenario') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.origin') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.scope') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.duration') }}</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{{ $t('crowdsec.decisions.actions') }}</th>
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
                >
                  {{ $t('common.delete') }}
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
import Layout from '../components/Layout.vue'
import { crowdsecApi, type CrowdSecDecision } from '../api'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const decisions = ref<CrowdSecDecision[]>([])
const total = ref(0)
const loading = ref(false)
const error = ref('')
const isEnabled = ref(false)

const filter = ref({ value: '', type: '', scenario: '' })

let refreshTimer: ReturnType<typeof setInterval> | null = null

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
      crowdsecApi.listDecisions(),
      crowdsecApi.status(),
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
  if (!confirm(t('crowdsec.decisions.confirmDelete', { id }))) return
  error.value = ''
  try {
    await crowdsecApi.deleteDecision(id)
    await load()
  } catch (e: any) {
    error.value = e.response?.data?.error ?? e.message
  }
}

onMounted(() => {
  load()
  refreshTimer = setInterval(load, 10000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>
