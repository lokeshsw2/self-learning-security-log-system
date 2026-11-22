// Typed client for the Python API (logparser/web.py).

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json }

export interface IngestResult {
  ingest_id: string
  records: number
  parsed: number
  pending: number
  dlq: number
  new_groups: number
}

export interface Stream {
  id: string
  kind: "file" | "kafka"
  target: string
  ingest_id: string
  lines: number
  parsed: number
  pending: number
  running: boolean
  error: string | null
}

export interface Overview {
  events: number
  event_sources: number
  invalid: number
  unparsed: number
  ingests: { ingest_id: string; parsed: number; unparsed: number; first_at: string }[]
  by_class: { class_uid: number; class_name: string; n: number }[]
  meta: { rules: Record<string, number>; groups: number; sources: number; queue: Record<string, number> }
  streams: Stream[]
}

export interface EventRow {
  time: string
  class_uid: number
  class_name: string
  activity_id: number
  severity_id: number
  status_id: number
  src_ip: string
  dst_ip: string
  user_name: string
  vendor_name: string
  product_name: string
  lp_source: string
  lp_group_id: string
  parser_rule: string
  mapping_rule: string
  lp_parser_version: number
  lp_mapping_version: number
  valid: number
  errors: string
  ingest_id: string
  raw_id: number
  fields: Record<string, Json>
  event: Record<string, Json>
  message: string
}

export interface UnparsedRow {
  received_at: string
  ingest_id: string
  raw_id: number
  lp_source: string
  lp_group_id: string
  status: string
  reason: string
  message: string
}

export interface SourceRow {
  source: string
  vendor: string | null
  product: string | null
  source_rule: string | null
  lines: number
  keys: string[]
  groups: number
  parsed_groups: number
  mapped_groups: number
  quarantined: boolean
}

export interface GroupRow {
  signature: string
  source: string
  template: string
  count: number
  status: string
  format: string
  parser_rule: string | null
  mapping_rule: string | null
  parse_failures: number
}

export interface RuleVersion {
  rule_id: string
  version: number
  kind: string
  status: string
  body: Json
  meta: { created_by?: string; note?: string; verification?: Json; [k: string]: Json | undefined }
  created_at: number
}

export interface GroupDetail extends GroupRow {
  bucket: string
  labels: Json
  detail: Record<string, Json>
  signatures: string[]
  samples: { raw: string; tag: string | null }[]
  stats: Record<string, Json>
  rules: Record<string, { rule_id: string; versions: RuleVersion[] }[]>
  decisions: { at: number; scope: string; question: string; answer: string; answered_by: string; tier: string }[]
  operations: { at: number; op: string; target: string; params: string; tier: string; by: string; status: string }[]
}

export interface RuleRow {
  rule_id: string
  kind: string
  version: number
  created_by: string | null
  created_at: number
  summary: string
}

export interface RuleDetail {
  rule_id: string
  versions: RuleVersion[]
  used_by_groups: string[]
}

export interface QueueItem {
  name: string
  key: string
  status: string
  payload: Record<string, Json>
  created_at: number
  attempts: number
}

export type Role = "source-naming" | "grouping-repair" | "parser-gen" | "ocsf-mapping" | "longtail"

export interface LearnResult {
  role: Role
  key: string
  saved: boolean
  reason: string | null
  at: number
}

export interface LearnRun {
  id: string
  roles: Role[]
  limit: number
  budget_usd: number
  model: string
  spent_usd: number
  running: boolean
  started: number
  finished: number | null
  role: Role | null
  error: string | null
  current: { role: Role; key: string; iteration: number } | null
  summary: Record<string, Record<string, Json>>
  results: LearnResult[]
}

export interface LearnStatus {
  models: { id: string; input: number; output: number }[]
  default_model: string
  last_audit: (Record<string, Json> & { at: number }) | null
  key_configured: boolean
  waiting: Record<Role, number>
  run: LearnRun | null
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init)
  const j = await r.json()
  if (j && typeof j === "object" && "error" in j && j.error) throw new Error(String(j.error))
  return j as T
}

const qs = (p: Record<string, string | number | undefined>) =>
  new URLSearchParams(Object.entries(p).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])).toString()

export const api = {
  overview: () => call<Overview>("/api/overview"),
  ingest: (lines: string[], ingestId: string, final = false) =>
    call<IngestResult>(`/api/ingest?${qs({ ingest_id: ingestId, final: final ? 1 : undefined })}`, {
      method: "POST",
      body: lines.join("\n"),
    }),
  events: (p: { ingest_id?: string; source?: string; group?: string; class_uid?: string; q?: string; limit?: number; offset?: number }) =>
    call<{ total: number; rows: EventRow[] }>(`/api/events?${qs(p)}`),
  unparsed: (p: { ingest_id?: string; group?: string } = {}) =>
    call<{ rows: UnparsedRow[]; by_group: { lp_group_id: string; source: string; reason: string; n: number; example: string }[] }>(
      `/api/unparsed?${qs(p)}`,
    ),
  sources: () => call<SourceRow[]>("/api/sources"),
  groups: (source: string) => call<GroupRow[]>(`/api/groups?${qs({ source })}`),
  group: (signature: string) => call<GroupDetail>(`/api/group?${qs({ signature })}`),
  rules: (kind: string, q: string) => call<RuleRow[]>(`/api/rules?${qs({ kind, q })}`),
  rule: (rule_id: string) => call<RuleDetail>(`/api/rule?${qs({ rule_id })}`),
  queue: () => call<QueueItem[]>("/api/queue"),
  startStream: (kind: string, target: string) =>
    call<Stream>("/api/streams", { method: "POST", body: JSON.stringify({ kind, target }) }),
  learn: () => call<LearnStatus>("/api/learn"),
  startLearn: (roles: Role[], limit: number, budget_usd: number, model: string) =>
    call<LearnStatus>("/api/learn", { method: "POST", body: JSON.stringify({ roles, limit, budget_usd, model }) }),
  audit: () => call<Record<string, Json>>("/api/audit", { method: "POST" }),
  stopLearn: () => call<LearnStatus>("/api/learn/stop", { method: "POST" }),
  stopStream: (id: string) => call<{ stopped: boolean }>(`/api/streams/stop?${qs({ id })}`, { method: "POST" }),
}

export const fmt = (n: number | string | undefined | null) => (Number(n) || 0).toLocaleString()

export function ago(t?: number) {
  if (!t) return ""
  const d = Date.now() / 1000 - t
  if (d < 90) return `${Math.round(d)}s ago`
  if (d < 5400) return `${Math.round(d / 60)}m ago`
  if (d < 172800) return `${Math.round(d / 3600)}h ago`
  return `${Math.round(d / 86400)}d ago`
}

/** Format/program part of a source key, without the stream label (matches the API's grouping). */
export const sourceKey = (s: string) => (s.includes("|") ? s.split("|").slice(1).join("|") : s)
