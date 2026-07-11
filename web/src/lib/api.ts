// Thin typed client over the Skryol REST API.

const BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiError(body?.error || res.statusText, res.status);
  }
  return body as T;
}

export const api = {
  get: <T>(p: string) => request<T>(p),
  post: <T>(p: string, body?: unknown) =>
    request<T>(p, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(p: string, body?: unknown) =>
    request<T>(p, { method: "PUT", body: body ? JSON.stringify(body) : undefined }),
  del: (p: string) => request<void>(p, { method: "DELETE" }),
};

// ---- Types (mirror the Go models) ----

export type AssetType = "ip" | "fqdn" | "domain" | "cidr";

export interface Asset {
  id: string;
  type: AssetType;
  value: string;
  label: string;
  notes: string;
  enabled: boolean;
  rescan: boolean;
  created_at: string;
  updated_at: string;
}

export interface AssetSummary {
  asset_id: string;
  type: AssetType;
  value: string;
  label: string;
  enabled: boolean;
  last_scan_id?: string;
  status?: string;
  score?: number;
  grade?: string;
  highest_cvss: number;
  cve_count: number;
  critical_count: number;
  open_ports_count: number;
  last_scanned_at?: string;
}

export interface TrendPoint {
  date: string;
  avg_score: number;
}

export interface Dashboard {
  total_assets: number;
  enabled_assets: number;
  scanned_assets: number;
  average_score: number;
  critical_issues: number;
  total_cves: number;
  grade_distribution: Record<string, number>;
  assets: AssetSummary[];
  trend: TrendPoint[];
}

export interface Scan {
  id: string;
  asset_id: string;
  started_at: string;
  finished_at?: string;
  status: "ok" | "partial" | "failed";
  score?: number;
  grade?: string;
  highest_cvss: number;
  cve_count: number;
  critical_count: number;
  open_ports_count: number;
  score_delta?: number;
  raw_json?: unknown;
  error?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  asset_id: string;
  target_ip: string;
  kind: string;
  severity: string;
  cvss: number;
  key: string;
  detail?: Record<string, unknown>;
  created_at: string;
}

export interface ScanDetail {
  scan: Scan;
  findings: Finding[];
}

export interface ScorePoint {
  at: string;
  score: number;
  grade: string;
}

export interface FindingChange {
  kind: string;
  key: string;
  target_ip: string;
  severity: string;
  cvss: number;
  detail?: Record<string, unknown>;
}

export interface DiffSummary {
  from_scan_id: string;
  to_scan_id: string;
  added: FindingChange[];
  removed: FindingChange[];
  cvss_changed: { kind: string; key: string; target_ip: string; from_cvss: number; to_cvss: number }[];
  score_from?: number;
  score_to?: number;
  score_delta: number;
  grade_from?: string;
  grade_to?: string;
  was_online: boolean;
  online: boolean;
  went_offline: boolean;
  came_online: boolean;
}

export interface ShodanKey {
  id: string;
  label: string;
  enabled: boolean;
  rate_per_second: number;
  query_credits: number;
  scan_credits: number;
  plan: string;
  health: string;
  last_error?: string;
  last_used_at?: string;
  last_checked_at?: string;
  created_at: string;
  updated_at: string;
}

export type ChannelType = "shoutrrr" | "greenapi" | "whatsapp_web";

export interface ChannelConfig {
  url?: string;
  instance_id?: string;
  token?: string;
  api_url?: string;
  base_url?: string;
  username?: string;
  password?: string;
  phone?: string;
}

export interface Channel {
  id: string;
  type: ChannelType;
  label: string;
  enabled: boolean;
  needs_credentials: boolean;
  config: ChannelConfig;
  created_at: string;
  updated_at: string;
}

export interface AlertRule {
  id: string;
  scope: "global" | "asset";
  asset_id?: string;
  condition: string;
  params?: Record<string, unknown>;
  enabled: boolean;
  cooldown_seconds: number;
  severity: string;
  label: string;
  channel_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface AlertEvent {
  id: string;
  rule_id: string;
  asset_id: string;
  condition: string;
  severity: string;
  fired_at: string;
  dedup_key: string;
  payload?: Record<string, unknown>;
  delivered?: Record<string, string>;
}

export interface ScoringWeights {
  cve_critical: number;
  cve_high: number;
  cve_medium: number;
  cve_low: number;
  verified_multiplier: number;
  default_password: number;
  remote_desktop: number;
  exposed_database: number;
  anonymous_smb: number;
  smb_share: number;
  cert_issue: number;
  weak_tls: number;
  mqtt_exposed: number;
  sensitive_port: number;
}

export interface Settings {
  scoring_weights: ScoringWeights;
  schedule: string;
  max_hosts_per_asset: number;
  max_concurrency: number;
  retention_days: number;
  auth_enabled: boolean;
  encryption_configured: boolean;
  version: string;
}
