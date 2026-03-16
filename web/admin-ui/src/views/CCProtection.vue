<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">{{ $t('ccProtection.title') }}</h2>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- LB Backends -->
        <div class="bg-white rounded-xl shadow-sm p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="text-sm font-semibold text-gray-700">{{ $t('ccProtection.backends') }}</h3>
            <button @click="showBackendForm = !showBackendForm" class="text-xs text-blue-600">{{ $t('ccProtection.addBackend') }}</button>
          </div>

          <div v-if="showBackendForm" class="flex gap-2 mb-3">
            <input v-model="backendForm.backend_host" :placeholder="$t('ccProtection.backendHost')" class="input flex-1 text-sm" />
            <input v-model.number="backendForm.backend_port" :placeholder="$t('ccProtection.backendPort')" type="number" class="input w-20 text-sm" />
            <input v-model="backendForm.host_code" :placeholder="$t('ccProtection.hostCode')" class="input w-32 text-sm" />
            <button @click="addBackend" class="btn-primary text-xs">{{ $t('common.add') }}</button>
          </div>

          <div class="space-y-1">
            <div v-for="b in backends" :key="b.id"
                 class="flex items-center justify-between text-xs bg-gray-50 rounded px-2 py-1.5">
              <span class="font-mono">{{ b.backend_host }}:{{ b.backend_port }}</span>
              <div class="flex items-center gap-2">
                <span :class="b.is_healthy ? 'text-green-600' : 'text-red-500'">
                  {{ b.is_healthy ? $t('ccProtection.healthy') : $t('ccProtection.unhealthy') }}
                </span>
                <button @click="deleteBackend(b.id)" class="text-red-500 flex items-center">
                  <X :size="14" />
                </button>
              </div>
            </div>
            <p v-if="!backends.length" class="text-xs text-gray-400 text-center py-2">{{ $t('ccProtection.noBackends') }}</p>
          </div>
        </div>

        <!-- Hotlink Config -->
        <div class="bg-white rounded-xl shadow-sm p-4">
          <h3 class="text-sm font-semibold text-gray-700 mb-3">{{ $t('ccProtection.hotlink') }}</h3>
          <div class="space-y-3">
            <input v-model="hotlinkForm.host_code" :placeholder="$t('ccProtection.hostCode')" class="input text-sm w-full" />
            <div class="flex items-center gap-3">
              <label class="flex items-center gap-1 text-sm">
                <input type="checkbox" v-model="hotlinkForm.enabled" />
                {{ $t('ccProtection.enabled') }}
              </label>
              <label class="flex items-center gap-1 text-sm">
                <input type="checkbox" v-model="hotlinkForm.allow_empty_referer" />
                {{ $t('ccProtection.allowEmptyReferer') }}
              </label>
            </div>
            <input v-model="hotlinkForm.redirect_url" :placeholder="$t('ccProtection.redirectUrl')" class="input text-sm w-full" />
            <button @click="saveHotlink" class="btn-primary text-sm">{{ $t('common.save') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { X } from 'lucide-vue-next'
import { ccApi } from '../api'
import Layout from '../components/Layout.vue'

const { t } = useI18n()

const backends = ref<any[]>([])
const showBackendForm = ref(false)
const backendForm = ref({ host_code: '', backend_host: '', backend_port: 8080 })
const hotlinkForm = ref({ host_code: '', enabled: true, allow_empty_referer: true, redirect_url: '' })

async function load() {
  const r = await ccApi.listBackends()
  backends.value = r.data.data
}

async function addBackend() {
  await ccApi.createBackend(backendForm.value)
  load()
}

async function deleteBackend(id: string) {
  await ccApi.deleteBackend(id)
  load()
}

async function saveHotlink() {
  await ccApi.upsertHotlink(hotlinkForm.value)
  alert(t('ccProtection.hotlinkSaved'))
}

onMounted(load)
</script>
