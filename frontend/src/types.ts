export type User = {
  id: number;
  name: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  active: boolean;
};
export type Asset = {
  id: number;
  name: string;
  category: string;
  criticality: number;
  exposure: string;
  owner: string;
};
export type Finding = {
  id: number;
  title: string;
  description: string;
  cve_id: string | null;
  cvss_score: number | null;
  score_source: string;
  severity: string;
  asset: Asset;
  status: string;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  due_at: string | null;
  remediated_at: string | null;
  occurrences: number;
  assignee_id: number | null;
  overdue: boolean;
  locator: string;
  source: string;
  revision: number;
  history?: {
    from_status: string | null;
    to_status: string;
    note: string;
    created_at: string;
  }[];
  activities?: { kind: string; note: string; created_at: string }[];
  risk_history?: {
    score: number;
    created_at: string;
    inputs: Record<string, unknown>;
  }[];
};
export type Dashboard = {
  total: number;
  unique_vulnerabilities: number;
  active: number;
  verified: number;
  accepted: number;
  severity: Record<string, number>;
  statuses: Record<string, number>;
  overdue: number;
  average_remediation_days: number | null;
  risk_total: number;
  aging: Record<string, number>;
  asset_distribution: { asset: string; count: number }[];
  trend: { date: string; risk: number }[];
  performance: {
    name: string;
    assigned: number;
    verified: number;
    overdue: number;
  }[];
};
export type ImportJob = {
  id: number;
  filename: string;
  adapter: string;
  status: string;
  created_count: number;
  duplicate_count: number;
  error: string | null;
  created_at: string;
};
export type Notification = {
  id: number;
  message: string;
  finding_id: number | null;
  created_at: string;
};
export type Sync = {
  watermark: string | null;
  last_attempt: string | null;
  last_success: string | null;
  last_error: string | null;
  requested: boolean;
  running: boolean;
  api_key_configured: boolean;
};
export type CVE = {
  id: string;
  description: string;
  cvss_score: number | null;
  cvss_version: string | null;
  severity: string;
  nvd_status: string;
  published_at: string | null;
  modified_at: string | null;
  cvss_vector?: string | null;
  references?: { url: string; source: string }[];
  affected_products?: Record<string, string>[];
};
export type Policy = {
  low: number;
  medium: number;
  high: number;
  critical: number;
  internet_multiplier: number;
  unknown_baseline: number;
  version: number;
};
export type Audit = {
  id: number;
  actor_id: number | null;
  action: string;
  target: string;
  created_at: string;
};
