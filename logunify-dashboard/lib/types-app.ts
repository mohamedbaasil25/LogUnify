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
}
export interface AlertView {
  summary: AlertSummary;
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
