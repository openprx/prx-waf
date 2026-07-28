<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">{{ $t('crowdsec.title') }}</h2>

      <!-- Status Banner -->
      <div
        :class="status.enabled ? 'bg-green-50 border-green-200' : 'bg-yellow-50 border-yellow-200'"
        class="border rounded-lg p-4 mb-6 flex items-center justify-between"
      >
        <div class="flex items-center gap-3">
          <component :is="status.enabled ? ShieldCheck : AlertTriangle"
            :size="24"
            :class="status.enabled ? 'text-green-600' : 'text-yellow-500'" />
          <div>
            <div class="font-semibold" :class="status.enabled ? 'text-green-800' : 'text-yellow-800'">
              {{ status.enabled ? $t('crowdsec.active') : $t('crowdsec.inactive') }}
            </div>
            <div class="text-sm" :class="status.enabled ? 'text-green-600' : 'text-yellow-600'">
              {{ status.enabled ? `LAPI: ${status.lapi_url}` : (status.connection_msg || $t('crowdsec.enableBelow')) }}
            </div>
          </div>
        </div>
        <div v-if="status.cache_stats" class="text-right text-sm text-green-700">
          <div>{{ status.cache_stats.total_cached }} {{ $t('crowdsec.decisionsCached') }}</div>
          <div>{{ status.cache_stats.hit_rate_pct.toFixed(1) }}% {{ $t('crowdsec.hitRate') }}</div>
        </div>
      </div>

      <!-- Config Form -->
      <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-700 mb-4">{{ $t('crowdsec.settings') }}</h3>

        <div class="space-y-4">
          <!-- Enable toggle -->
          <div class="flex items-center gap-3">
            <input type="checkbox" id="enabled" v-model="form.enabled" class="w-4 h-4 text-blue-600" />
            <label for="enabled" class="font-medium text-gray-700">{{ $t('crowdsec.enableIntegration') }}</label>
          </div>

          <!-- Mode -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('crowdsec.mode') }}</label>
            <select v-model="form.mode" class="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500">
              <option value="bouncer">{{ $t('crowdsec.modeBouncer') }}</option>
              <option value="appsec">{{ $t('crowdsec.modeAppsec') }}</option>
              <option value="both">{{ $t('crowdsec.modeBoth') }}</option>
            </select>
          </div>

          <!-- LAPI URL -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('crowdsec.lapiUrl') }}</label>
            <input
              v-model="form.lapi_url"
              type="text"
              placeholder="http://127.0.0.1:8080"
              class="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <!-- API Key -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              {{ $t('crowdsec.apiKey') }}
              <span v-if="config.api_key_set" class="text-xs text-green-600 ml-2">{{ $t('crowdsec.keyIsSet') }}</span>
            </label>
            <input
              v-model="form.api_key"
              type="password"
              :placeholder="config.api_key_set ? '(unchanged)' : 'Enter bouncer API key'"
              class="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <!-- Update frequency -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('crowdsec.updateFrequency') }}</label>
            <input
              v-model.number="form.update_frequency_secs"
              type="number"
              min="5"
              max="3600"
              class="w-32 border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <!-- Fallback action -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('crowdsec.fallbackAction') }}</label>
            <select v-model="form.fallback_action" class="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500">
              <option value="allow">{{ $t('crowdsec.fallbackAllow') }}</option>
              <option value="block">{{ $t('crowdsec.fallbackBlock') }}</option>
              <option value="log">{{ $t('crowdsec.fallbackLog') }}</option>
            </select>
          </div>

          <!-- AppSec section -->
          <template v-if="form.mode === 'appsec' || form.mode === 'both'">
            <div class="border-t pt-4 mt-4">
              <h4 class="font-medium text-gray-700 mb-3">{{ $t('crowdsec.appsecSettings') }}</h4>
              <div class="space-y-3">
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('crowdsec.appsecEndpoint') }}</label>
                  <input
                    v-model="form.appsec_endpoint"
                    type="text"
                    placeholder="http://127.0.0.1:7422"
                    class="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-1">
                    {{ $t('crowdsec.appsecKey') }}
                    <span v-if="config.appsec_key_set" class="text-xs text-green-600 ml-2">{{ $t('crowdsec.keyIsSet') }}</span>
                  </label>
                  <input
                    v-model="form.appsec_key"
                    type="password"
                    :placeholder="config.appsec_key_set ? '(unchanged)' : 'Enter AppSec API key'"
                    class="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
            </div>
          </template>
        </div>

        <!-- Buttons -->
        <div class="flex gap-3 mt-6">
          <button
            @click="saveConfig"
            :disabled="saving"
            class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
          >
            {{ saving ? $t('crowdsec.saving') : $t('crowdsec.saveConfig') }}
          </button>
          <button
            @click="testConnection"
            :disabled="testing"
            class="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700 disabled:opacity-50"
          >
            {{ testing ? $t('crowdsec.testing') : $t('crowdsec.testConnection') }}
          </button>
        </div>

        <!-- Test result -->
        <div v-if="testResult" class="mt-3 p-3 rounded" :class="testResult.success ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'">
          {{ testResult.message }}
        </div>

        <!-- Save result -->
        <div v-if="saveMsg" class="mt-3 p-3 bg-green-50 text-green-800 rounded">{{ saveMsg }}</div>
        <div v-if="saveError" class="mt-3 p-3 bg-red-50 text-red-800 rounded">{{ saveError }}</div>
      </div>

      <!-- Setup wizard hint -->
      <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div class="font-semibold text-blue-800 mb-1">{{ $t('crowdsec.cliWizard') }}</div>
        <div class="text-sm text-blue-700">
          Run <code class="bg-blue-100 px-1 rounded">prx-waf crowdsec setup</code> for an interactive setup guide,
          or <code class="bg-blue-100 px-1 rounded">prx-waf crowdsec test</code> to verify connectivity from the command line.
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import Layout from '../components/Layout.vue'
import { crowdsecApi, type CrowdSecConfigReq, type CrowdSecTestReq } from '../api'
import { ShieldCheck, AlertTriangle } from 'lucide-vue-next'

const status = ref<any>({ enabled: false })
const config = ref<any>({ api_key_set: false, appsec_key_set: false })

const form = ref({
  enabled: false,
  mode: 'bouncer',
  lapi_url: 'http://127.0.0.1:8080',
  api_key: '',
  update_frequency_secs: 10,
  fallback_action: 'allow',
  appsec_endpoint: '',
  appsec_key: '',
})

const saving = ref(false)
const testing = ref(false)
const testResult = ref<any>(null)
const saveMsg = ref('')
const saveError = ref('')

async function loadStatus() {
  try {
    const r = await crowdsecApi.status()
    status.value = r.data
  } catch {}
}

async function loadConfig() {
  try {
    const r = await crowdsecApi.getConfig()
    config.value = r.data
    form.value.enabled = r.data.enabled ?? false
    form.value.mode = r.data.mode ?? 'bouncer'
    form.value.lapi_url = r.data.lapi_url ?? 'http://127.0.0.1:8080'
    form.value.update_frequency_secs = r.data.update_frequency_secs ?? 10
    form.value.fallback_action = r.data.fallback_action ?? 'allow'
    form.value.appsec_endpoint = r.data.appsec_endpoint ?? ''
  } catch {}
}

async function saveConfig() {
  saving.value = true
  saveMsg.value = ''
  saveError.value = ''
  try {
    const payload: CrowdSecConfigReq = {
      enabled: form.value.enabled,
      mode: form.value.mode,
      lapi_url: form.value.lapi_url,
      update_frequency_secs: form.value.update_frequency_secs,
      fallback_action: form.value.fallback_action,
    }
    if (form.value.api_key) payload.api_key = form.value.api_key
    if (form.value.appsec_endpoint) payload.appsec_endpoint = form.value.appsec_endpoint
    if (form.value.appsec_key) payload.appsec_key = form.value.appsec_key

    await crowdsecApi.updateConfig(payload)
    saveMsg.value = 'Configuration saved. Restart prx-waf to apply changes.'
    await loadConfig()
    await loadStatus()
  } catch (e: any) {
    saveError.value = e.response?.data?.error ?? e.message
  } finally {
    saving.value = false
  }
}

async function testConnection() {
  testing.value = true
  testResult.value = null
  try {
    const payload: CrowdSecTestReq = { lapi_url: form.value.lapi_url }
    if (form.value.api_key) payload.api_key = form.value.api_key
    const r = await crowdsecApi.test(payload)
    testResult.value = r.data
  } catch (e: any) {
    testResult.value = { success: false, message: e.response?.data?.error ?? e.message }
  } finally {
    testing.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadStatus(), loadConfig()])
})
</script>
