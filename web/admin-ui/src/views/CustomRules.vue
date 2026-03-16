<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-gray-800">{{ $t('nav.customRules') }}</h2>
        <button @click="showForm = !showForm" class="btn-primary">+ {{ $t('rules.newRule') }}</button>
      </div>

      <!-- Editor form -->
      <div v-if="showForm" class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold mb-3">{{ $t('rules.createRule') }}</h3>
        <div class="grid grid-cols-2 gap-3 mb-3">
          <input v-model="form.name" :placeholder="$t('common.name')" class="input" />
          <input v-model="form.host_code" :placeholder="$t('rules.host')" class="input" />
          <input v-model.number="form.priority" :placeholder="$t('rules.priority')" type="number" class="input" />
          <select v-model="form.action" class="input">
            <option value="block">{{ $t('security.block') }}</option>
            <option value="allow">{{ $t('security.allow') }}</option>
            <option value="log">{{ $t('botManagement.logOnly') }}</option>
          </select>
        </div>
        <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('rules.script') }}</label>
        <textarea
          v-model="form.script"
          placeholder="// Rhai script&#10;// request.ip, request.path, request.method, request.headers"
          class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono h-32 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <div class="flex gap-2 mt-3">
          <button @click="createRule" class="btn-primary text-sm">{{ $t('common.create') }}</button>
          <button @click="showForm = false" class="btn-secondary text-sm">{{ $t('common.cancel') }}</button>
        </div>
      </div>

      <!-- Rules list -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('common.name') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('rules.host') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('rules.priority') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.action') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('common.enabled') }}</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="r in rules" :key="r.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 font-medium">{{ r.name }}</td>
              <td class="px-4 py-3 font-mono text-gray-500">{{ r.host_code }}</td>
              <td class="px-4 py-3">{{ r.priority }}</td>
              <td class="px-4 py-3">
                <span :class="r.action === 'block' ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'"
                      class="text-xs px-2 py-0.5 rounded font-medium">{{ r.action }}</span>
              </td>
              <td class="px-4 py-3"><Badge :active="r.enabled" :yes="$t('common.yes')" :no="$t('common.no')" /></td>
              <td class="px-4 py-3 text-right">
                <button @click="deleteRule(r.id)" class="text-red-500 hover:text-red-700 text-xs">{{ $t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="!rules.length">
              <td colspan="6" class="px-4 py-6 text-center text-gray-400">{{ $t('rules.noCustomRules') }}</td>
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
import { customRulesApi } from '../api'
import Layout from '../components/Layout.vue'
import Badge from '../components/Badge.vue'

const { t } = useI18n()

const rules = ref<any[]>([])
const showForm = ref(false)
const form = ref({ name: '', host_code: '*', priority: 100, action: 'block', script: '', conditions: [] })

async function load() {
  const r = await customRulesApi.list()
  rules.value = r.data.data
}

async function createRule() {
  await customRulesApi.create({ ...form.value, conditions: [] })
  showForm.value = false
  load()
}

async function deleteRule(id: string) {
  if (!confirm(t('rules.confirmDelete'))) return
  await customRulesApi.delete(id)
  load()
}

onMounted(load)
</script>
