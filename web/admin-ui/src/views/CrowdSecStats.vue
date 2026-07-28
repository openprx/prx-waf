<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold text-gray-800">{{ $t('crowdsec.stats.title') }}</h2>
        <button
          @click="load"
          class="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          {{ $t('common.refresh') }}
        </button>
      </div>

      <div v-if="!stats.total_decisions && !loading" class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
        <span class="text-yellow-800">{{ $t('crowdsec.stats.notActive') }}
          <router-link to="/crowdsec-settings" class="underline">{{ $t('nav.settings') }}</router-link>.
        </span>
      </div>

      <!-- Top stat cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="bg-white rounded-lg shadow p-5">
          <div class="text-3xl font-bold text-blue-600">{{ stats.total_decisions ?? 0 }}</div>
          <div class="text-sm text-gray-500 mt-1">{{ $t('crowdsec.stats.cachedDecisions') }}</div>
        </div>
        <div class="bg-white rounded-lg shadow p-5">
          <div class="text-3xl font-bold text-green-600">{{ stats.cache?.hits ?? 0 }}</div>
          <div class="text-sm text-gray-500 mt-1">{{ $t('crowdsec.stats.cacheHits') }}</div>
        </div>
        <div class="bg-white rounded-lg shadow p-5">
          <div class="text-3xl font-bold text-purple-600">
            {{ stats.cache ? stats.cache.hit_rate_pct.toFixed(1) + '%' : '-' }}
          </div>
          <div class="text-sm text-gray-500 mt-1">{{ $t('crowdsec.stats.hitRate') }}</div>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Decisions by type -->
        <div class="bg-white rounded-lg shadow p-5">
          <h3 class="font-semibold text-gray-700 mb-4">{{ $t('crowdsec.stats.byType') }}</h3>
          <div v-if="Object.keys(stats.by_type ?? {}).length === 0" class="text-gray-400 text-sm">{{ $t('common.noData') }}</div>
          <div v-else class="space-y-3">
            <div
              v-for="(count, type) in stats.by_type"
              :key="type"
              class="flex items-center gap-3"
            >
              <span
                :class="{
                  'bg-red-100 text-red-700': type === 'ban',
                  'bg-yellow-100 text-yellow-700': type === 'captcha',
                  'bg-orange-100 text-orange-700': type === 'throttle',
                  'bg-gray-100 text-gray-700': !['ban','captcha','throttle'].includes(String(type)),
                }"
                class="px-2 py-0.5 rounded text-xs font-medium w-20 text-center"
              >{{ type }}</span>
              <div class="flex-1 bg-gray-100 rounded-full h-2">
                <div
                  class="bg-blue-500 h-2 rounded-full"
                  :style="{ width: maxTypeCount > 0 ? (Number(count) / maxTypeCount * 100) + '%' : '0%' }"
                ></div>
              </div>
              <span class="text-sm font-medium text-gray-600 w-12 text-right">{{ count }}</span>
            </div>
          </div>
        </div>

        <!-- Top scenarios -->
        <div class="bg-white rounded-lg shadow p-5">
          <h3 class="font-semibold text-gray-700 mb-4">{{ $t('crowdsec.stats.topScenarios') }}</h3>
          <div v-if="topScenarios.length === 0" class="text-gray-400 text-sm">{{ $t('common.noData') }}</div>
          <div v-else class="space-y-2">
            <div
              v-for="[scenario, count] in topScenarios"
              :key="scenario"
              class="flex items-center justify-between"
            >
              <span class="text-sm text-gray-700 truncate max-w-xs" :title="scenario">{{ scenario }}</span>
              <span class="text-sm font-medium text-gray-500 ml-2">{{ count }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Sync indicator -->
      <div class="mt-6 bg-white rounded-lg shadow p-4 flex items-center gap-3">
        <div class="w-2.5 h-2.5 rounded-full" :class="stats.total_decisions != null ? 'bg-green-400 animate-pulse' : 'bg-gray-300'"></div>
        <div class="text-sm text-gray-600">
          <span v-if="stats.total_decisions != null">
            {{ $t('crowdsec.stats.syncActive') }} — {{ stats.total_decisions }} {{ $t('crowdsec.stats.decisionsInCache') }}
            ({{ stats.cache?.hits ?? 0 }} {{ $t('crowdsec.stats.hits') }} / {{ stats.cache?.misses ?? 0 }} {{ $t('crowdsec.stats.misses') }})
          </span>
          <span v-else>{{ $t('crowdsec.stats.syncNotRunning') }}</span>
        </div>
        <div class="ml-auto text-xs text-gray-400">{{ $t('crowdsec.stats.lastRefresh') }} {{ lastRefresh }}</div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import Layout from '../components/Layout.vue'
import { crowdsecApi } from '../api'

const stats = ref<any>({})
const loading = ref(false)
const lastRefresh = ref('-')

const maxTypeCount = computed(() => {
  if (!stats.value.by_type) return 0
  return Math.max(...Object.values(stats.value.by_type as Record<string, number>), 1)
})

const topScenarios = computed(() => {
  if (!stats.value.by_scenario) return []
  return Object.entries(stats.value.by_scenario as Record<string, number>)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
})

async function load() {
  loading.value = true
  try {
    const r = await crowdsecApi.stats()
    stats.value = r.data
    lastRefresh.value = new Date().toLocaleTimeString()
  } catch {
    // silent
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
