import { drizzle, DrizzleD1Database } from 'drizzle-orm/d1';
import { eq, gt, and } from 'drizzle-orm';
import * as schema from './schema';

export type DB = DrizzleD1Database<typeof schema>;

export function createDb(d1: D1Database): DB {
  return drizzle(d1, { schema });
}

// --- Enrollment Tokens ---

export async function getTokenByValue(db: DB, tokenValue: string) {
  return db.select().from(schema.enrollmentTokens).where(eq(schema.enrollmentTokens.token, tokenValue)).get();
}

export async function incrementTokenUseCount(db: DB, id: string, currentUseCount: number, maxUses: number) {
  const updated = currentUseCount + 1;
  await db.update(schema.enrollmentTokens).set({
    useCount: updated,
    used: updated >= maxUses ? 1 : 0,
  }).where(eq(schema.enrollmentTokens.id, id));
}

// --- Agents ---

export async function insertAgent(
  db: DB,
  agent: {
    agentId: string;
    orgId: string;
    publicKey: string;
    keyId: string;
    hostname: string;
    platform: string;
    platformVersion: string;
    deviceId: string;
    hardwareUuid?: string;
  },
) {
  await db.insert(schema.agents).values({
    agentId: agent.agentId,
    orgId: agent.orgId,
    publicKey: agent.publicKey,
    keyId: agent.keyId,
    hostname: agent.hostname,
    platform: agent.platform,
    platformVersion: agent.platformVersion,
    deviceId: agent.deviceId,
    hardwareUuid: agent.hardwareUuid || null,
    lastSeenAt: new Date().toISOString(),
  });
}

export async function getAgent(db: DB, agentId: string) {
  return db.select().from(schema.agents).where(eq(schema.agents.agentId, agentId)).get();
}

export async function getActiveAgentByHardwareUuid(db: DB, hardwareUuid: string) {
  return db.select().from(schema.agents)
    .where(and(eq(schema.agents.hardwareUuid, hardwareUuid), eq(schema.agents.status, 'active')))
    .get();
}

export async function getAgentByHardwareUuid(db: DB, hardwareUuid: string) {
  return db.select().from(schema.agents)
    .where(eq(schema.agents.hardwareUuid, hardwareUuid))
    .get();
}

export async function revokeAgent(db: DB, agentId: string) {
  await db.update(schema.agents).set({ status: 'revoked' }).where(eq(schema.agents.agentId, agentId));
}

export async function deleteAgent(db: DB, agentId: string, deviceId: string | null) {
  if (deviceId) {
    await db.delete(schema.deviceChecks).where(eq(schema.deviceChecks.deviceId, deviceId));
    await db.delete(schema.attestations).where(eq(schema.attestations.deviceId, deviceId));
  }
  await db.delete(schema.agents).where(eq(schema.agents.agentId, agentId));
}

export async function updateLastSeen(db: DB, agentId: string, timestamp: string) {
  await db.update(schema.agents).set({ lastSeenAt: timestamp }).where(eq(schema.agents.agentId, agentId));
}

// --- Attestations ---

export async function insertAttestation(
  db: DB,
  attestation: {
    attestationId: string;
    agentId: string;
    deviceId: string;
    schemaVersion: string;
    collectedAt: string;
    payload: string;
    signature: string;
  },
) {
  await db.insert(schema.attestations).values({
    attestationId: attestation.attestationId,
    agentId: attestation.agentId,
    deviceId: attestation.deviceId,
    schemaVersion: attestation.schemaVersion,
    collectedAt: attestation.collectedAt,
    payload: attestation.payload,
    signature: attestation.signature,
  });
}

export async function getAttestation(db: DB, attestationId: string) {
  return db.select().from(schema.attestations).where(eq(schema.attestations.attestationId, attestationId)).get();
}

// --- Device Checks ---

export async function upsertDeviceCheck(
  db: DB,
  check: { deviceId: string; checkKey: string; checkValue: string; observedAt: string; source: string },
) {
  await db
    .insert(schema.deviceChecks)
    .values({
      deviceId: check.deviceId,
      checkKey: check.checkKey,
      checkValue: check.checkValue,
      observedAt: check.observedAt,
      source: check.source,
    })
    .onConflictDoUpdate({
      target: [schema.deviceChecks.deviceId, schema.deviceChecks.checkKey],
      set: {
        checkValue: check.checkValue,
        observedAt: check.observedAt,
        source: check.source,
      },
    });
}

export async function getDeviceChecks(db: DB, deviceId: string) {
  return db.select().from(schema.deviceChecks).where(eq(schema.deviceChecks.deviceId, deviceId)).all();
}

// --- Devices (agents as devices) ---

export async function listDevices(db: DB, limit: number, cursor?: string) {
  const query = cursor
    ? db
        .select()
        .from(schema.agents)
        .where(gt(schema.agents.deviceId, cursor))
        .orderBy(schema.agents.deviceId)
        .limit(limit + 1)
    : db
        .select()
        .from(schema.agents)
        .orderBy(schema.agents.deviceId)
        .limit(limit + 1);

  const rows = await query.all();

  let nextCursor: string | null = null;
  if (rows.length > limit) {
    rows.pop();
    const last = rows[rows.length - 1];
    nextCursor = last.deviceId ? btoa(last.deviceId) : null;
  }

  return { devices: rows, next_cursor: nextCursor };
}

export async function getDeviceByDeviceId(db: DB, deviceId: string) {
  return db.select().from(schema.agents).where(eq(schema.agents.deviceId, deviceId)).get();
}

// --- Rekey ---

export async function rekeyAgent(db: DB, agentId: string, newPublicKey: string, newKeyId: string) {
  await db.update(schema.agents).set({ publicKey: newPublicKey, keyId: newKeyId }).where(eq(schema.agents.agentId, agentId));
}

// --- Admin API Keys ---

export async function getAdminApiKey(db: DB, keyHash: string) {
  return db.select().from(schema.adminApiKeys).where(eq(schema.adminApiKeys.keyHash, keyHash)).get();
}
