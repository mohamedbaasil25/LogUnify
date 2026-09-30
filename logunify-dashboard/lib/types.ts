export interface Metrics {
  uptime_seconds: number;
  received: number;
  processed: number;
  dropped: number;
  throughput_eps: { "1s": number; "10s": number; "60s": number };
  compression_ratio: number;
  anomalies: number;
  templates: number;
  noise_reduced_pct: number;
  integrity: { batches_sealed: number; batches_anchored: number };
  threat_intel: { enabled: boolean; iocs: number; matches: number };
}

export interface ThroughputSeries {
  series: { ts: number; count: number }[];
}

/** Subset of the ECS document the dashboard reads; everything is optional because sources vary. */
export interface EcsDoc {
  "@timestamp": string;
  message?: string;
  source?: { ip?: string; port?: number; geo?: { country_iso_code?: string; country_name?: string } };
  host?: { name?: string };
  observer?: { vendor?: string; product?: string };
  event?: { action?: string; reason?: string; dataset?: string; ingested?: string; original?: string };
  logunify?: {
    source_format?: string;
    anomaly?: { score?: number; model_ready?: boolean };
    template?: { id?: number; text?: string };
    ti?: { matched?: boolean; match_count?: number; matched_field?: string; matches?: { type: string; value: string; feed: string; field: string }[] };
  };
  threat?: {
    technique?: { id?: string; name?: string };
    tactic?: { name?: string };
    indicator?: { type?: string; provider?: string; confidence?: string; description?: string; reference?: string };
  };
  [k: string]: unknown;
}

export interface RecentLogs {
  count: number;
  items: EcsDoc[];
}

export interface AnchorReceipt {
  tx_id: string;
  batch_id: string;
  merkle_root: string;
  timestamp: string;
  block_number: number;
  channel: string;
  status: string;
  mock: boolean;
}

export interface BatchSummary {
  id: string;
  merkle_root: string;
  count: number;
  sealed_at: string;
  anchor: AnchorReceipt | null;
}

export interface BatchList {
  batch_size: number;
  pending_records: number;
  items: BatchSummary[];
}

export type SourceType = "syslog" | "http" | "api";
export type SourceFormat = "auto" | "syslog" | "json" | "cef" | "text";

export interface LogSource {
  id: string;
  name: string;
  type: SourceType;
  format: SourceFormat;
  status: "active" | "registered";
  config: Record<string, string | number>;
  tags: string[];
  created_at: string;
  received: number;
  has_token: boolean;
  token: string | null;
}

export interface SourceCreate {
  name: string;
  type: SourceType;
  format: SourceFormat;
  tags: string[];
  protocol?: "udp" | "tcp";
  port?: number;
  url?: string;
  poll_interval_s?: number;
}

export interface ProofStep {
  hash: string;
  position: "left" | "right";
}

export interface ProofBundle {
  batch_id: string;
  index: number;
  record: Record<string, unknown>;
  leaf_hash: string;
  merkle_root: string;
  proof: ProofStep[];
}

export interface VerifyResult {
  valid: boolean;
  proof_valid: boolean;
  leaf_hash: string;
  computed_root: string;
  anchored: boolean;
  anchor_root_matches: boolean | null;
  tx_id: string | null;
}

export interface AuditResult {
  batch_id: string;
  records: number;
  recomputed_root: string;
  sealed_root: string;
  sealed_root_intact: boolean;
  altered_indexes: number[];
  anchored: boolean;
  ledger_root_matches: boolean | null;
}
