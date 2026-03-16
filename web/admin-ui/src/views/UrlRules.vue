<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">{{ $t('urlRules.title') }}</h2>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RuleTable
          :title="$t('urlRules.allowUrls')"
          color="green"
          :rows="allowUrls"
          @add="addAllowUrl"
          @delete="deleteAllowUrl"
          :field-label="$t('urlRules.urlPattern')"
          field-key="url_pattern"
        />
        <RuleTable
          :title="$t('urlRules.blockUrls')"
          color="red"
          :rows="blockUrls"
          @add="addBlockUrl"
          @delete="deleteBlockUrl"
          :field-label="$t('urlRules.urlPattern')"
          field-key="url_pattern"
        />
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { urlRulesApi } from '../api'
import Layout from '../components/Layout.vue'
import RuleTable from '../components/RuleTable.vue'

useI18n()

const allowUrls = ref<any[]>([])
const blockUrls = ref<any[]>([])

async function load() {
  const [a, b] = await Promise.all([urlRulesApi.listAllow(), urlRulesApi.listBlock()])
  allowUrls.value = a.data.data
  blockUrls.value = b.data.data
}

async function addAllowUrl(data: any) {
  await urlRulesApi.createAllow({ ...data, match_type: 'prefix' })
  load()
}
async function deleteAllowUrl(id: string) { await urlRulesApi.deleteAllow(id); load() }
async function addBlockUrl(data: any) {
  await urlRulesApi.createBlock({ ...data, match_type: 'prefix' })
  load()
}
async function deleteBlockUrl(id: string) { await urlRulesApi.deleteBlock(id); load() }

onMounted(load)
</script>
