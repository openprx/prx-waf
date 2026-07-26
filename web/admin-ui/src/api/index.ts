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

// ─── Semantic Observations (Lane 2 shadow telemetry) ──────────────────────────
export interface ObservationSignal {
  detector?: string | null
  attack?: string | null
  field?: string | null
  scope?: string | null
  confidence?: number | null
  rule_key?: string | null
  provenance?: string | null
}
export interface Observation {
  id: string
  host_code: string
  client_ip: string
  req_id: string
  scope: string
  request_score: number
  recommendation: string
  degraded: boolean
  exhausted: boolean
  pipeline: string
  schema_version: number
  created_at: string
  signals: ObservationSignal[]
}
export interface LabeledCount {
  label: string
  count: number
}
export interface ObservationFilters {
  host_code?: string
  attack?: string
  rule_key?: string
  min_score?: number
  from?: string
  to?: string
  page?: number
  page_size?: number
}
export const observationsApi = {
  list: (params?: ObservationFilters) => api.get('/api/observations', { params }),
  stats: (hours?: number) => api.get('/api/observations/stats', { params: { hours } }),
}

// ─── Custom Rules ─────────────────────────────────────────────────────────────
export const customRulesApi = {
  list: (hostCode?: string) => api.get('/api/custom-rules', { params: { host_code: hostCode } }),
  create: (data: any) => api.post('/api/custom-rules', data),
  delete: (id: string) => api.delete(`/api/custom-rules/${id}`),
}

// ─── Bot Detection ────────────────────────────────────────────────────────────
// All five routes are admin-only, reads included: the list is a detection
// signature set plus every whitelist that lets a request skip bot detection.
export interface BotPattern {
  /** Numeric row id for operator patterns; the rule id string for built-ins. */
  id: number | string
  /** Detection id as it appears in security events (`BOT-007`, `BOT-USER-3`). */
  rule_id?: string
  name: string
  pattern: string
  action: string
  description?: string | null
  enabled: boolean
  source: 'builtin' | 'user'
  category: 'good' | 'bad' | 'user'
  created_at?: string
  updated_at?: string
}
export interface BotPatternLimits {
  max_user_patterns: number
  max_pattern_len: number
  max_name_len: number
}
export interface BotPatternList {
  builtin: BotPattern[]
  user: BotPattern[]
  /** What the request path is running now — disabled rows are excluded. */
  active_user_patterns: number
  limits: BotPatternLimits
}
export interface BotTestMatch {
  id: string
  name: string
  action: string
  source: 'builtin' | 'user'
}
export interface BotTestResult {
  user_agent: string
  verdict: 'allow' | 'block' | 'no-match'
  matches: BotTestMatch[]
}
export const botPatternsApi = {
  list: () => api.get('/api/bot-patterns'),
  create: (data: { name: string; pattern: string; action: string; description?: string }) =>
    api.post('/api/bot-patterns', data),
  update: (id: number, data: Partial<{ name: string; pattern: string; action: string; description: string; enabled: boolean }>) =>
    api.put(`/api/bot-patterns/${id}`, data),
  delete: (id: number) => api.delete(`/api/bot-patterns/${id}`),
  /** Evaluate a UA with the engine's own matcher (JS RegExp cannot parse `(?i)`). */
  test: (userAgent: string) => api.get('/api/bot-patterns/test', { params: { user_agent: userAgent } }),
}

// ─── OWASP CRS Rule Registry & Overrides ──────────────────────────────────────
// The registry is read straight from the live `waf_engine::OWASPCheck` — what is
// listed here is exactly what the request path walks, for the queried scope.
// Overrides are strictly subtractive (disable, or downgrade to log-only); there
// is no way to add a rule or escalate one to an unconditional deny here.
export interface RejectedRule {
  rule_id: string
  source: string
  reason: string
}
export interface SourceLoadError {
  source: string
  error: string
}
export interface RegistrySummary {
  declared: number
  enforced: number
  request_rules: number
  response_rules: number
  rejected: number
  rejected_rules: RejectedRule[]
  source_errors: SourceLoadError[]
  severity_defaulted: string[]
  action_defaulted: string[]
  used_embedded_fallback: boolean
  degraded: boolean
  /** Overrides in this scope that switch a rule off entirely — a hole, not a tuning knob. */
  disabled: number
  log_only: number
}
export interface RuleDescriptor {
  id: string
  crs_id: number
  name: string
  category: string
  source: string
  severity: string
  score: number
  paranoia: number
  phase: 'request' | 'response'
  declared_action: string
  /** What the request path does with a match in this scope, after overrides. */
  effective_action: 'score' | 'deny' | 'log' | 'disabled'
  state: 'active' | 'disabled' | 'log_only'
  enabled: boolean
  overridden: boolean
}
export interface RulesRegistry {
  scope: { host_code: string | null }
  summary: RegistrySummary
  rules: RuleDescriptor[]
}
export interface RuleOverride {
  id: number
  rule_id: string
  host_code: string | null
  enabled: boolean | null
  action_override: string | null
  note: string | null
  /** `false` = this override names a rule this build does not load; it is inert. */
  known_rule: boolean
  state: 'active' | 'disabled' | 'log_only' | 'invalid'
  created_at: string
  updated_at: string
}
export interface CreateRuleOverrideReq {
  rule_id: string
  host_code?: string | null
  enabled?: boolean | null
  action_override?: string | null
  note?: string | null
}
export interface UpdateRuleOverrideReq {
  enabled?: boolean | null
  action_override?: string | null
  note?: string | null
}
export interface RuleOverrideResult {
  success: boolean
  data: RuleOverride
  applied: boolean
  warning: string | null
}
export interface ReloadRulesReport {
  applied: number
  disabled: number
  log_only: number
  hosts: number
  unknown_rule_ids: string[]
  enforced_rules: number
}
export const rulesApi = {
  /** `host` omitted = the global layer; a host code narrows to what applies there. */
  registry: (host?: string) => api.get('/api/rules/registry', { params: { host } }),
  overrides: () => api.get('/api/rules/overrides'),
  createOverride: (data: CreateRuleOverrideReq) => api.post('/api/rules/overrides', data),
  updateOverride: (id: number, data: UpdateRuleOverrideReq) => api.put(`/api/rules/overrides/${id}`, data),
  deleteOverride: (id: number) => api.delete(`/api/rules/overrides/${id}`),
  reload: () => api.post('/api/rules/reload'),
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

// ─── Admin audit trail ────────────────────────────────────────────────────────
export interface AuditLogEntry {
  id: number
  admin_username: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  detail: { status?: number; outcome?: string } | null
  ip_addr: string | null
  created_at: string
}
export interface AuditLogFilters {
  admin_username?: string
  action?: string
  page?: number
  page_size?: number
}
export const auditApi = {
  list: (params?: AuditLogFilters) => api.get('/api/audit-log', { params }),
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
