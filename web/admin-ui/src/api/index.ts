import axios from 'axios'

const api = axios.create({
  baseURL: '/',
  timeout: 15000,
})

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Auto-logout on 401
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/ui/login'
    }
    return Promise.reject(err)
  }
)

export default api

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const authApi = {
  login: (username: string, password: string) =>
    api.post('/api/auth/login', { username, password }),
  logout: (refreshToken: string) =>
    api.post('/api/auth/logout', { refresh_token: refreshToken }),
  refresh: (refreshToken: string) =>
    api.post('/api/auth/refresh', { refresh_token: refreshToken }),
}

// ─── Hosts ────────────────────────────────────────────────────────────────────
export const hostsApi = {
  list: () => api.get('/api/hosts'),
  get: (id: string) => api.get(`/api/hosts/${id}`),
  create: (data: any) => api.post('/api/hosts', data),
  update: (id: string, data: any) => api.put(`/api/hosts/${id}`, data),
  delete: (id: string) => api.delete(`/api/hosts/${id}`),
}

// ─── IP Rules ─────────────────────────────────────────────────────────────────
export const ipRulesApi = {
  listAllow: (hostCode?: string) => api.get('/api/allow-ips', { params: { host_code: hostCode } }),
  createAllow: (data: any) => api.post('/api/allow-ips', data),
  deleteAllow: (id: string) => api.delete(`/api/allow-ips/${id}`),
  listBlock: (hostCode?: string) => api.get('/api/block-ips', { params: { host_code: hostCode } }),
  createBlock: (data: any) => api.post('/api/block-ips', data),
  deleteBlock: (id: string) => api.delete(`/api/block-ips/${id}`),
}

// ─── URL Rules ────────────────────────────────────────────────────────────────
export const urlRulesApi = {
  listAllow: (hostCode?: string) => api.get('/api/allow-urls', { params: { host_code: hostCode } }),
  createAllow: (data: any) => api.post('/api/allow-urls', data),
  deleteAllow: (id: string) => api.delete(`/api/allow-urls/${id}`),
  listBlock: (hostCode?: string) => api.get('/api/block-urls', { params: { host_code: hostCode } }),
  createBlock: (data: any) => api.post('/api/block-urls', data),
  deleteBlock: (id: string) => api.delete(`/api/block-urls/${id}`),
}

// ─── Security Events ──────────────────────────────────────────────────────────
export const eventsApi = {
  listAttackLogs: (params?: any) => api.get('/api/attack-logs', { params }),
  listSecurityEvents: (params?: any) => api.get('/api/security-events', { params }),
}

// ─── Custom Rules ─────────────────────────────────────────────────────────────
export const customRulesApi = {
  list: (hostCode?: string) => api.get('/api/custom-rules', { params: { host_code: hostCode } }),
  create: (data: any) => api.post('/api/custom-rules', data),
  delete: (id: string) => api.delete(`/api/custom-rules/${id}`),
}

// ─── Certificates ─────────────────────────────────────────────────────────────
export const certsApi = {
  list: (hostCode?: string) => api.get('/api/certificates', { params: { host_code: hostCode } }),
  upload: (data: any) => api.post('/api/certificates', data),
  delete: (id: string) => api.delete(`/api/certificates/${id}`),
}

// ─── CC Protection ────────────────────────────────────────────────────────────
export const ccApi = {
  getHotlink: (hostCode: string) => api.get('/api/hotlink-config', { params: { host_code: hostCode } }),
  upsertHotlink: (data: any) => api.post('/api/hotlink-config', data),
  listBackends: (hostCode?: string) => api.get('/api/lb-backends', { params: { host_code: hostCode } }),
  createBackend: (data: any) => api.post('/api/lb-backends', data),
  deleteBackend: (id: string) => api.delete(`/api/lb-backends/${id}`),
}

// ─── Statistics ───────────────────────────────────────────────────────────────
export const statsApi = {
  overview: () => api.get('/api/stats/overview'),
  timeseries: (params?: any) => api.get('/api/stats/timeseries', { params }),
}

// ─── Notifications ────────────────────────────────────────────────────────────
export const notifApi = {
  list: (hostCode?: string) => api.get('/api/notifications', { params: { host_code: hostCode } }),
  create: (data: any) => api.post('/api/notifications', data),
  delete: (id: string) => api.delete(`/api/notifications/${id}`),
  log: () => api.get('/api/notifications/log'),
  test: (id: string) => api.post(`/api/notifications/${id}/test`),
}

// ─── Status ───────────────────────────────────────────────────────────────────
export const systemApi = {
  status: () => api.get('/api/status'),
  reload: () => api.post('/api/reload'),
}

// ─── Cluster ──────────────────────────────────────────────────────────────────
export const clusterApi = {
  status: () => api.get('/api/cluster/status'),
  listNodes: () => api.get('/api/cluster/nodes'),
  getNode: (id: string) => api.get(`/api/cluster/nodes/${id}`),
  generateToken: (ttl_ms?: number) => api.post('/api/cluster/token', { ttl_ms }),
  removeNode: (node_id: string) => api.post('/api/cluster/nodes/remove', { node_id }),
}
