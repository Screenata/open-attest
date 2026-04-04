import { drizzle } from 'drizzle-orm/d1';
import * as schema from '../src/schema';
import type { DB } from '../src/db';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id TEXT PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  org_id TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  revoked INTEGER DEFAULT 0,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  key_id TEXT NOT NULL,
  hostname TEXT,
  platform TEXT NOT NULL,
  platform_version TEXT,
  device_id TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS attestations (
  attestation_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
);

CREATE TABLE IF NOT EXISTS device_checks (
  device_id TEXT NOT NULL,
  check_key TEXT NOT NULL,
  check_value TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  source TEXT,
  PRIMARY KEY (device_id, check_key)
);

CREATE TABLE IF NOT EXISTS admin_api_keys (
  key_hash TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  label TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

export async function initDb(d1: D1Database): Promise<void> {
  const statements = SCHEMA.split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    await d1.prepare(stmt).run();
  }
}

export function createTestDb(d1: D1Database): DB {
  return drizzle(d1, { schema });
}

export async function seedToken(
  d1: D1Database,
  overrides: {
    id?: string;
    token?: string;
    org_id?: string;
    used?: number;
    revoked?: number;
    expires_at?: string;
  } = {},
): Promise<{ id: string; token: string; org_id: string }> {
  const db = createTestDb(d1);
  const id = overrides.id ?? `tok_${crypto.randomUUID()}`;
  const token = overrides.token ?? `enroll_${crypto.randomUUID()}`;
  const org_id = overrides.org_id ?? `org_${crypto.randomUUID()}`;

  await db.insert(schema.enrollmentTokens).values({
    id,
    token,
    orgId: org_id,
    used: overrides.used ?? 0,
    revoked: overrides.revoked ?? 0,
    expiresAt: overrides.expires_at ?? new Date(Date.now() + 3600_000).toISOString(),
  });

  return { id, token, org_id };
}

export async function seedAgent(
  d1: D1Database,
  publicKeyBase64: string,
  overrides: {
    agent_id?: string;
    org_id?: string;
    device_id?: string;
    status?: string;
  } = {},
): Promise<{ agent_id: string; device_id: string; org_id: string }> {
  const db = createTestDb(d1);
  const agent_id = overrides.agent_id ?? `agent_${crypto.randomUUID()}`;
  const org_id = overrides.org_id ?? `org_${crypto.randomUUID()}`;
  const device_id = overrides.device_id ?? `dev_${crypto.randomUUID()}`;

  await db.insert(schema.agents).values({
    agentId: agent_id,
    orgId: org_id,
    publicKey: publicKeyBase64,
    keyId: `key_${crypto.randomUUID()}`,
    hostname: 'test-host',
    platform: 'macos',
    platformVersion: '14.0',
    deviceId: device_id,
    status: overrides.status ?? 'active',
  });

  return { agent_id, device_id, org_id };
}

export async function seedAdminKey(d1: D1Database, apiKey: string, org_id: string): Promise<void> {
  const db = createTestDb(d1);
  const keyBytes = new TextEncoder().encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
  const hashArray = new Uint8Array(hashBuffer);
  let keyHash = '';
  for (const b of hashArray) {
    keyHash += b.toString(16).padStart(2, '0');
  }

  await db.insert(schema.adminApiKeys).values({
    keyHash,
    orgId: org_id,
    label: 'test-key',
  });
}

export async function generateEd25519Keypair(): Promise<{
  publicKeyBase64: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeyRaw));
  return {
    publicKeyBase64,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

export async function signPayload(privateKey: CryptoKey, payload: string): Promise<string> {
  const data = new TextEncoder().encode(payload);
  const signature = await crypto.subtle.sign('Ed25519', privateKey, data);
  return bytesToBase64(new Uint8Array(signature));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
