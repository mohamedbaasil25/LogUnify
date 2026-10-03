import type { EcsDoc } from "./types";

// ---- session ----------------------------------------------------------------------------------------------------
export type Role = "viewer" | "analyst" | "admin";
export interface Me {
  sub: string;
  role: Role;
  auth: "jwt" | "api-key" | "disabled";
  exp: number | null;
  expires_in_s: number | null;
}

// ---- alerts / CERT-In ---------------------------------------------------------------------------------------------
export type AlertStatus = "open" | "acknowledged" | "reported" | "closed";
export interface AlertSummary {
  id: string;
  status: AlertStatus;
  created_at: string;
  due_at: string;
  seconds_remaining: number;
  overdue: boolean;
  technique: string;
  technique_name: string;
  score: number;
  host: string | null;
  affected_ip: string | null;
  remote_ip: string | null;
  occurrences: number;
  notification: string;
  on_time: boolean | null;
  assignee: string | null;
}
export interface AlertView {
  summary: AlertSummary;
  assignee: { to: string; by: string; at: number } | null;
  trigger: { score: number; threshold: number; technique_id: string; technique_name: string; tactic: string; basis: string; critical_match: boolean };
  notification: { status: string; cycles: number; sent_at: number | null };
  ack: { by: string; at: number; note?: string } | null;
  reported: { by: string; at: number; via?: string; reference?: string; note?: string } | null;
  closed: { by: string; at: number; resolution?: string; note?: string } | null;
  evidence: { record_sha256?: string; event_id?: string | null };
}
export interface CertGap {
  field: string;
  label: string;
}
export interface CertReport {
  deadline: {
    report_due_at: { utc: string; ist: string };
    clock_started_at: { utc: string; ist: string };
    seconds_remaining: number;
    overdue: boolean;
    submit_via: { email: string; phone: string; fax: string };
  };
  incident_type: { annexure_i: { id: string; label: string }[]; origin: string; other_specify: string | null };
  data_quality_warnings?: string[];
  completeness: { needs_analyst: CertGap[]; needs_configuration: CertGap[]; to_confirm: CertGap[]; note: string };
}
export interface AlertEvent {
  seq: number;
  at: number;
  actor: string;
  kind: string;
  data: Record<string, unknown>;
}

export interface AlertNote {
  seq: number;
  at: number;
  by: string;
  text: string;
}

// ---- search / saved searches ----------------------------------------------------------------------------------------
export interface LogQuery {
  q?: string;
  from?: string;
  to?: string;
  format?: string;
  min_score?: number;
}
export interface AlertQuery {
  status?: string;
  assignee?: string;
}
export interface SavedSearch {
  id: string;
  owner: string;
  name: string;
  kind: "logs" | "alerts";
  shared: boolean;
  query: LogQuery & AlertQuery;
  created_at: number;
  updated_at: number;
}
export interface SearchCoverage {
  events_held: number;
  oldest: string | null;
  newest: string | null;
  note: string;
}
export interface LogSearchResult {
  total: number;
  offset: number;
  items: EcsDoc[];
  coverage: SearchCoverage;
}

// ---- trace --------------------------------------------------------------------------------------------------------
export interface TraceResult {
  event_id: string;
  verdict: "verified" | "mismatch" | "raw_not_archived";
  raw_archived: boolean;
  checks: Record<string, boolean | null>;
  normalized: EcsDoc | null;
  record_sha256?: string;
  integrity_reference?: { batch_id: string; index: number; merkle_root: string; anchor_tx_id: string | null; anchored_at: string | null } | null;
  envelope?: Record<string, unknown>;
  raw?: { sha256: string; size: number; stored_at: number; text?: string };
}

// ---- operations / governance ---------------------------------------------------------------------------------------
export interface SystemInfo {
  version: string;
  bus: string;
  mock_generator: boolean;
  auth_mode: string;
  worker_id: string | null;
  consumer_alive: boolean;
  consumer_restarts: number;
  ready: boolean;
  problems: string[];
  taxonomy_mode: string;
  raw_archive: boolean;
  docs_enabled: boolean;
}
export interface DlqView {
  stats: { written: number; lost_full: number; lost_queue: number; lost_io: number; queued: number; file_bytes: number };
  by_reason: Record<string, number>;
  preview: { event_id: string; reason: string; stage: string; ts: number; source_id: string | null; error: string; hint: string | null }[];
}
export interface AuditRow {
  seq: number;
  ts: number;
  actor: string;
  role: string;
  auth: string;
  action: string;
  resource: string;
  outcome: string;
  client: string | null;
  detail: Record<string, unknown>;
  hash: string;
}
export interface ComplianceControl {
  framework: string;
  id: string;
  title: string;
  requirement: string;
  status: "met" | "partial" | "gap" | "manual";
  evidence: string;
}
export interface ComplianceReport {
  generated_at: string;
  report_sha256: string;
  summary: Record<string, { met: number; partial: number; gap: number; manual: number }>;
  controls: ComplianceControl[];
}

// ---- alert calibration ----------------------------------------------------------------------------------------------------
export interface SweepRow {
  threshold: number;
  events: number;
  alerts: number;
  suppressed: number;
  techniques: Record<string, number>;
  alerts_per_day: number | null;
}
export interface PreviewAlert {
  technique: string;
  technique_name: string;
  asset: string;
  host: string | null;
  score: number;
  at: string | null;
  occurrences: number;
  basis: string;
  event_id: string | null;
  message: string;
}
export interface Suppression {
  id: string;
  technique: string;
  asset: string;
  reason: string;
  created_by: string;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
  revoked_by: string | null;
  active: boolean;
  hits: number;
  last_at: number | null;
  last_event_id: string | null;
}
export interface FeedbackTechnique {
  technique: string;
  closed: number;
  false_positive: number;
  not_reportable: number;
  resolved: number;
  fp_rate: number | null;
}
export interface NoisyAsset {
  technique: string;
  asset: string;
  closed: number;
  false_positive: number;
  not_reportable: number;
  resolved: number;
  candidate: boolean;
}
export interface Calibration {
  configured: { threshold: number; critical_techniques: string[]; require_rule_basis: boolean; dedup_minutes: number; tagging_threshold: number | null };
  candidate: { threshold: number; critical_techniques: string[] };
  scope: { format: string | null; from: string | null; feedback_days: number };
  replay: {
    coverage: { events_held: number; events_in_scope: number; buffer: number; oldest: number | null; newest: number | null; note: string };
    confidence: { level: "low" | "medium" | "high"; window_hours: number; events: number; why: string };
    model_ready_events: number;
    histogram: { from: number; to: number; count: number }[];
    percentiles: Record<string, number>;
    funnel: { step: string; count: number; why: string }[];
    sweep: SweepRow[];
    recommendation: { threshold: number | null; text: string };
    preview: { alerts: number; events: number; suppressed: number; items: PreviewAlert[]; truncated: boolean };
    note: string;
  };
  feedback: {
    alerts_total: number;
    closed: number;
    resolutions: Record<string, number>;
    false_positive_rate: number | null;
    techniques: FeedbackTechnique[];
    noisiest_assets: NoisyAsset[];
    cert_in: { reported: number; on_time: number; on_time_rate: number | null; overdue_now: number; active_now: number };
    since_days: number;
    per_day: { day: string; alerts: number }[];
  };
  suppressions: Suppression[];
}
export interface CalibrationParams {
  threshold?: string;
  critical?: string;
  format?: string;
  from?: string;
  feedback_days?: string;
  capacity_per_day?: string;
}
