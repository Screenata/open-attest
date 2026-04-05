import { sqliteTable, text, integer, primaryKey } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const enrollmentTokens = sqliteTable('enrollment_tokens', {
  id: text('id').primaryKey(),
  token: text('token').unique().notNull(),
  orgId: text('org_id').notNull(),
  used: integer('used').default(0).notNull(),
  revoked: integer('revoked').default(0).notNull(),
  maxUses: integer('max_uses').default(1).notNull(),
  useCount: integer('use_count').default(0).notNull(),
  expiresAt: text('expires_at').notNull(),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export const agents = sqliteTable('agents', {
  agentId: text('agent_id').primaryKey(),
  orgId: text('org_id').notNull(),
  publicKey: text('public_key').notNull(),
  keyId: text('key_id').notNull(),
  hostname: text('hostname'),
  platform: text('platform').notNull(),
  platformVersion: text('platform_version'),
  deviceId: text('device_id').unique(),
  hardwareUuid: text('hardware_uuid'),
  status: text('status').notNull().default('active'),
  enrolledAt: text('enrolled_at').notNull().default(sql`(datetime('now'))`),
  lastSeenAt: text('last_seen_at'),
});

export const attestations = sqliteTable('attestations', {
  attestationId: text('attestation_id').primaryKey(),
  agentId: text('agent_id').notNull().references(() => agents.agentId),
  deviceId: text('device_id').notNull(),
  schemaVersion: text('schema_version').notNull(),
  collectedAt: text('collected_at').notNull(),
  payload: text('payload').notNull(),
  signature: text('signature').notNull(),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export const deviceChecks = sqliteTable(
  'device_checks',
  {
    deviceId: text('device_id').notNull(),
    checkKey: text('check_key').notNull(),
    checkValue: text('check_value').notNull(),
    observedAt: text('observed_at').notNull(),
    source: text('source'),
  },
  (table) => [primaryKey({ columns: [table.deviceId, table.checkKey] })],
);

export const adminApiKeys = sqliteTable('admin_api_keys', {
  keyHash: text('key_hash').primaryKey(),
  orgId: text('org_id').notNull(),
  label: text('label'),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});
