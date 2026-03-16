<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">{{ $t('ipRules.title') }}</h2>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Allow list -->
        <RuleTable
          :title="$t('ipRules.allowList')"
          color="green"
          :rows="allowIps"
          @add="addAllowIp"
          @delete="deleteAllowIp"
          :field-label="$t('ipRules.ipCidr')"
          field-key="ip_cidr"
          :host-code="hostCode"
        />
        <!-- Block list -->
        <RuleTable
          :title="$t('ipRules.blockList')"
          color="red"
          :rows="blockIps"
          @add="addBlockIp"
          @delete="deleteBlockIp"
          :field-label="$t('ipRules.ipCidr')"
          field-key="ip_cidr"
          :host-code="hostCode"
        />
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ipRulesApi } from '../api'
import Layout from '../components/Layout.vue'
import RuleTable from '../components/RuleTable.vue'

useI18n()

const hostCode = ref('')
const allowIps = ref<any[]>([])
const blockIps = ref<any[]>([])

async function load() {
  const [a, b] = await Promise.all([ipRulesApi.listAllow(), ipRulesApi.listBlock()])
  allowIps.value = a.data.data
  blockIps.value = b.data.data
}

async function addAllowIp(data: any) { await ipRulesApi.createAllow(data); load() }
async function deleteAllowIp(id: string) { await ipRulesApi.deleteAllow(id); load() }
async function addBlockIp(data: any) { await ipRulesApi.createBlock(data); load() }
async function deleteBlockIp(id: string) { await ipRulesApi.deleteBlock(id); load() }

onMounted(load)
</script>
