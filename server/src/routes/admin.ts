import { eq } from 'drizzle-orm';
import { apiError } from '../errors';
import { createDb } from '../db';
import * as schema from '../schema';
import type { Env } from '../types';

function authenticateSecret(request: Request, env: Env): Response | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return apiError('FORBIDDEN', 'Missing Authorization header');
  }
  const token = authHeader.slice(7);
  if (!env.ADMIN_SECRET || token !== env.ADMIN_SECRET) {
    return apiError('FORBIDDEN', 'Invalid admin secret');
  }
  return null;
}

// POST /v1/admin/api-keys — create an admin API key
export async function handleCreateApiKey(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  let body: { org_id: string; label?: string };
  try {
    body = await request.json();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.org_id) {
    return apiError('VALIDATION_ERROR', 'Missing required field: org_id');
  }

  // Generate a random API key
  const apiKey = `oak_${crypto.randomUUID().replace(/-/g, '')}`;

  // Hash it for storage
  const keyBytes = new TextEncoder().encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
  const hashArray = new Uint8Array(hashBuffer);
  let keyHash = '';
  for (const b of hashArray) {
    keyHash += b.toString(16).padStart(2, '0');
  }

  const db = createDb(env.DB);
  await db.insert(schema.adminApiKeys).values({
    keyHash,
    orgId: body.org_id,
    label: body.label || null,
  });

  return new Response(
    JSON.stringify({
      api_key: apiKey,
      org_id: body.org_id,
      label: body.label || null,
      note: 'Save this key — it cannot be retrieved again.',
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

// POST /v1/admin/tokens — create an enrollment token
export async function handleCreateToken(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  let body: { org_id: string; expires_in_hours?: number; max_uses?: number };
  try {
    body = await request.json();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.org_id) {
    return apiError('VALIDATION_ERROR', 'Missing required field: org_id');
  }

  const ttlHours = body.expires_in_hours ?? 24;
  const maxUses = body.max_uses ?? 1;
  const expiresAt = new Date(Date.now() + ttlHours * 3600_000).toISOString();
  const token = `oat_${crypto.randomUUID().replace(/-/g, '')}`;
  const id = `tok_${crypto.randomUUID()}`;

  const db = createDb(env.DB);
  await db.insert(schema.enrollmentTokens).values({
    id,
    token,
    orgId: body.org_id,
    maxUses,
    expiresAt,
  });

  const enrollUrl = new URL(`/enroll/${token}`, request.url).toString();

  return new Response(
    JSON.stringify({
      token,
      enroll_url: enrollUrl,
      org_id: body.org_id,
      expires_at: expiresAt,
      expires_in_hours: ttlHours,
      max_uses: maxUses,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

// GET /v1/admin/api-keys — list API keys (metadata only, no key values)
export async function handleListApiKeys(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  const db = createDb(env.DB);
  const keys = await db.select().from(schema.adminApiKeys).all();

  return new Response(
    JSON.stringify({
      api_keys: keys.map((k) => ({
        key_hash_prefix: k.keyHash.slice(0, 8) + '...',
        org_id: k.orgId,
        label: k.label,
        created_at: k.createdAt,
      })),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

// DELETE /v1/admin/api-keys — delete an API key by hash prefix
export async function handleDeleteApiKey(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  let body: { key_hash_prefix: string };
  try {
    body = await request.json();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.key_hash_prefix) {
    return apiError('VALIDATION_ERROR', 'Missing required field: key_hash_prefix');
  }

  const prefix = body.key_hash_prefix.replace('...', '');
  const db = createDb(env.DB);
  const keys = await db.select().from(schema.adminApiKeys).all();
  const match = keys.find((k) => k.keyHash.startsWith(prefix));

  if (!match) {
    return apiError('NOT_FOUND', 'API key not found');
  }

  await db.delete(schema.adminApiKeys).where(eq(schema.adminApiKeys.keyHash, match.keyHash));

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// GET /v1/admin/tokens — list enrollment tokens
export async function handleListTokens(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  const db = createDb(env.DB);
  const tokens = await db.select().from(schema.enrollmentTokens).all();

  return new Response(
    JSON.stringify({
      tokens: tokens.map((t) => ({
        id: t.id,
        token_prefix: t.token.slice(0, 12) + '...',
        org_id: t.orgId,
        used: !!t.used,
        revoked: !!t.revoked,
        max_uses: t.maxUses,
        use_count: t.useCount,
        expires_at: t.expiresAt,
        created_at: t.createdAt,
        expired: new Date(t.expiresAt) < new Date(),
      })),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

// GET /v1/admin/status — server health + stats
export async function handleAdminStatus(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  const db = createDb(env.DB);

  const agents = await db.select().from(schema.agents).all();
  const activeAgents = agents.filter((a) => a.status === 'active');
  const revokedAgents = agents.filter((a) => a.status === 'revoked');

  const tokens = await db.select().from(schema.enrollmentTokens).all();
  const unusedTokens = tokens.filter((t) => !t.used && !t.revoked && new Date(t.expiresAt) > new Date());

  // Device compliance stats
  const now = Date.now();
  const FIFTEEN_MIN = 15 * 60 * 1000;
  const onlineAgents = activeAgents.filter((a) => a.lastSeenAt && (now - new Date(a.lastSeenAt).getTime()) < FIFTEEN_MIN);
  const offlineAgents = activeAgents.filter((a) => !a.lastSeenAt || (now - new Date(a.lastSeenAt).getTime()) >= FIFTEEN_MIN);

  // Check compliance per device: a device is compliant if disk_encryption=true AND firewall=true
  const allChecks = await db.select().from(schema.deviceChecks).all();
  const checksByDevice = new Map<string, Map<string, string>>();
  for (const c of allChecks) {
    if (!checksByDevice.has(c.deviceId)) checksByDevice.set(c.deviceId, new Map());
    checksByDevice.get(c.deviceId)!.set(c.checkKey, c.checkValue);
  }

  let compliant = 0;
  let nonCompliant = 0;
  for (const agent of activeAgents) {
    if (!agent.deviceId) continue;
    const checks = checksByDevice.get(agent.deviceId);
    if (!checks) { nonCompliant++; continue; }

    const diskEnc = checks.get('disk_encryption.enabled');
    const firewall = checks.get('firewall.enabled');
    const screenLockPw = checks.get('screen_lock.password_required');

    const diskOk = diskEnc && JSON.parse(diskEnc).value === true;
    const fwOk = firewall && JSON.parse(firewall).value === true;
    const slOk = screenLockPw && JSON.parse(screenLockPw).value === true;

    if (diskOk && fwOk && slOk) {
      compliant++;
    } else {
      nonCompliant++;
    }
  }

  return new Response(
    JSON.stringify({
      status: 'ok',
      version: '0.2.0',
      stats: {
        devices_total: activeAgents.length,
        devices_compliant: compliant,
        devices_non_compliant: nonCompliant,
        devices_online: onlineAgents.length,
        devices_offline: offlineAgents.length,
        agents_revoked: revokedAgents.length,
        tokens_available: unusedTokens.length,
        tokens_total: tokens.length,
      },
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}
