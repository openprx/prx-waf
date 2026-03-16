<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-gray-800">{{ $t('certificates.title') }}</h2>
        <button @click="showForm = !showForm" class="btn-primary">{{ $t('certificates.uploadCert') }}</button>
      </div>

      <!-- Upload form -->
      <div v-if="showForm" class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold mb-3">{{ $t('certificates.uploadTitle') }}</h3>
        <div class="grid grid-cols-2 gap-3 mb-3">
          <input v-model="form.host_code" :placeholder="$t('certificates.host')" class="input" />
          <input v-model="form.domain" :placeholder="$t('certificates.domain')" class="input" />
        </div>
        <textarea v-model="form.cert_pem" :placeholder="$t('certificates.certPem')" class="w-full input h-24 font-mono text-xs mb-2" />
        <textarea v-model="form.key_pem" :placeholder="$t('certificates.keyPem')" class="w-full input h-24 font-mono text-xs mb-2" />
        <div class="flex gap-2">
          <button @click="uploadCert" class="btn-primary text-sm">{{ $t('certificates.upload') }}</button>
          <button @click="showForm = false" class="btn-secondary text-sm">{{ $t('common.cancel') }}</button>
        </div>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('certificates.domain') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('certificates.host') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('certificates.issuer') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('certificates.expires') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('certificates.status') }}</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="c in certs" :key="c.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 font-mono">{{ c.domain }}</td>
              <td class="px-4 py-3 font-mono text-gray-500">{{ c.host_code }}</td>
              <td class="px-4 py-3 text-gray-500">{{ c.issuer || '-' }}</td>
              <td class="px-4 py-3 text-gray-500">{{ c.not_after ? new Date(c.not_after).toLocaleDateString() : '-' }}</td>
              <td class="px-4 py-3">
                <span :class="c.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'"
                      class="text-xs px-2 py-0.5 rounded font-medium">{{ c.status }}</span>
              </td>
              <td class="px-4 py-3 text-right">
                <button @click="deleteCert(c.id)" class="text-red-500 hover:text-red-700 text-xs">{{ $t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="!certs.length">
              <td colspan="6" class="px-4 py-6 text-center text-gray-400">{{ $t('certificates.noCerts') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { certsApi } from '../api'
import Layout from '../components/Layout.vue'

const { t } = useI18n()

const certs = ref<any[]>([])
const showForm = ref(false)
const form = ref({ host_code: '', domain: '', cert_pem: '', key_pem: '', auto_renew: true })

async function load() {
  const r = await certsApi.list()
  certs.value = r.data.data
}

async function uploadCert() {
  await certsApi.upload(form.value)
  showForm.value = false
  load()
}

async function deleteCert(id: string) {
  if (!confirm(t('certificates.confirmDelete'))) return
  await certsApi.delete(id)
  load()
}

onMounted(load)
</script>
