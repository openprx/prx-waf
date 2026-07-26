<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-gray-800">{{ $t('notifications.title') }}</h2>
        <button @click="showForm = !showForm" class="btn-primary">{{ $t('notifications.addConfig') }}</button>
      </div>

      <!-- Form -->
      <div v-if="showForm" class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold mb-3">{{ $t('notifications.newConfig') }}</h3>
        <div class="grid grid-cols-2 gap-3">
          <input v-model="form.name" :placeholder="$t('notifications.name')" class="input" />
          <select v-model="form.channel_type" class="input">
            <option value="webhook">{{ $t('notifications.webhook') }}</option>
            <option value="telegram">{{ $t('notifications.telegram') }}</option>
            <option value="email">{{ $t('notifications.email') }}</option>
          </select>
          <select v-model="form.event_type" class="input">
            <option value="attack_detected">{{ $t('notifications.attackDetected') }}</option>
            <option value="cert_expiry">{{ $t('notifications.certExpiry') }}</option>
            <!--
              No producer raises `high_traffic` yet: the WAF has no request-rate
              counter to compare against a threshold. Offering it as a selectable
              option would let an operator configure a channel that can never
              fire — the exact failure this screen already had for every event
              type. Disabled until a producer exists.
            -->
            <option value="high_traffic" disabled>
              {{ $t('notifications.highTraffic') }} ({{ $t('notifications.notAvailable') }})
            </option>
            <option value="backend_down">{{ $t('notifications.backendDown') }}</option>
          </select>
          <input v-model="form.host_code" :placeholder="$t('ccProtection.hostCode')" class="input" />
        </div>

        <!-- Channel config -->
        <div class="mt-3">
          <p class="text-xs font-medium text-gray-600 mb-1">{{ $t('notifications.channelConfig') }}</p>
          <textarea
            v-model="configJson"
            :placeholder="channelPlaceholder"
            class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono h-20 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div class="flex gap-2 mt-3">
          <button @click="createNotif" class="btn-primary text-sm">{{ $t('common.create') }}</button>
          <button @click="showForm = false" class="btn-secondary text-sm">{{ $t('common.cancel') }}</button>
        </div>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('notifications.name') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('notifications.event') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('notifications.channel') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('notifications.lastTriggered') }}</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="n in notifs" :key="n.id" class="hover:bg-gray-50">
              <td class="px-4 py-3">{{ n.name }}</td>
              <td class="px-4 py-3 text-gray-600">{{ n.event_type }}</td>
              <td class="px-4 py-3">
                <span class="bg-blue-100 text-blue-700 text-xs px-2 py-0.5 rounded font-medium">{{ n.channel_type }}</span>
              </td>
              <td class="px-4 py-3 text-gray-400 text-xs">
                {{ n.last_triggered ? new Date(n.last_triggered).toLocaleString() : $t('common.never') }}
              </td>
              <td class="px-4 py-3 text-right space-x-2">
                <button @click="testNotif(n.id)" class="text-blue-500 hover:text-blue-700 text-xs">{{ $t('common.test') }}</button>
                <button @click="deleteNotif(n.id)" class="text-red-500 hover:text-red-700 text-xs">{{ $t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="!notifs.length">
              <td colspan="5" class="px-4 py-6 text-center text-gray-400">{{ $t('notifications.noConfigs') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { notifApi } from '../api'
import { useI18n } from 'vue-i18n'
import Layout from '../components/Layout.vue'

const { t } = useI18n()
const notifs = ref<any[]>([])
const showForm = ref(false)
const form = ref({ name: '', event_type: 'attack_detected', channel_type: 'webhook', host_code: '' })
const configJson = ref('{}')

const channelPlaceholder = computed(() => {
  if (form.value.channel_type === 'webhook') return '{"url": "https://hooks.example.com/..."}'
  if (form.value.channel_type === 'telegram') return '{"bot_token": "...", "chat_id": "..."}'
  return '{"smtp_host": "smtp.gmail.com", "smtp_port": 587, "from": "waf@example.com", "to": ["admin@example.com"]}'
})

async function load() {
  const r = await notifApi.list()
  notifs.value = r.data.data
}

async function createNotif() {
  let cfg = {}
  try { cfg = JSON.parse(configJson.value) } catch (_) {}
  await notifApi.create({ ...form.value, config_json: cfg })
  showForm.value = false
  load()
}

async function deleteNotif(id: string) {
  if (!confirm(t('notifications.confirmDelete'))) return
  await notifApi.delete(id)
  load()
}

async function testNotif(id: string) {
  try {
    await notifApi.test(id)
    alert(t('notifications.testSent'))
  } catch (e: any) {
    alert(t('notifications.failed') + (e.response?.data?.error || e.message))
  }
}

onMounted(load)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50; }
</style>
