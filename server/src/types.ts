import { InferSelectModel } from 'drizzle-orm';
import * as schema from './schema';

// --- Wire format types ---

export type CheckValue =
  | { type: 'bool'; value: boolean }
  | { type: 'int'; value: number }
  | { type: 'string'; value: string }
  | { type: 'string_list'; value: string[] };

export type CheckResult = {
  key: string;
  value: CheckValue;
  observed_at: string;
  source: string;
  evidence?: Record<string, unknown>;
};

export type EnrollmentRequest = {
  token: string;
  public_key: string;
  hostname: string;
  platform: 'macos' | 'windows' | 'linux';
  platform_version: string;
  identity_anchors: {
    hardware_uuid?: string;
    serial_hash?: string;
  };
};

export type EnrollmentResponse = {
  agent_id: string;
  key_id: string;
  org_id: string;
  workspace_id?: string;
  config: {
    heartbeat_interval_seconds: number;
    snapshot_interval_seconds: number;
  };
};

export type AttestationPayload = {
  schema_version: string;
  attestation_id: string;
  collected_at: string;
  agent: { name: string; version: string; agent_id: string };
  device: {
    device_id: string;
    hostname: string;
    platform: string;
    platform_version: string;
    identity_anchors: { hardware_uuid?: string; serial_hash?: string };
  };
  user?: { username?: string; email?: string };
  checks: CheckResult[];
};

export type HeartbeatPayload = {
  device_id: string;
  agent_id: string;
  timestamp: string;
};

export type ErrorCode =
  | 'INVALID_REQUEST'
  | 'INVALID_SIGNATURE'
  | 'AGENT_REVOKED'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_ALREADY_USED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'ALREADY_ENROLLED'
  | 'VALIDATION_ERROR'
  | 'INTERNAL_ERROR';

export type ErrorEnvelope = {
  error: {
    code: ErrorCode;
    message: string;
    details: Record<string, unknown>;
  };
};

// --- DB row types (inferred from Drizzle schema) ---

export type AgentRow = InferSelectModel<typeof schema.agents>;
export type EnrollmentTokenRow = InferSelectModel<typeof schema.enrollmentTokens>;
export type AttestationRow = InferSelectModel<typeof schema.attestations>;
export type DeviceCheckRow = InferSelectModel<typeof schema.deviceChecks>;
export type AdminApiKeyRow = InferSelectModel<typeof schema.adminApiKeys>;

// --- Env ---

export interface Env {
  DB: D1Database;
  ADMIN_SECRET: string;
}
