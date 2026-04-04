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

  let body: { org_id: string; expires_in_hours?: number };
  try {
    body = await request.json();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.org_id) {
    return apiError('VALIDATION_ERROR', 'Missing required field: org_id');
  }

  const ttlHours = body.expires_in_hours ?? 24;
  const expiresAt = new Date(Date.now() + ttlHours * 3600_000).toISOString();
  const token = `oat_${crypto.randomUUID().replace(/-/g, '')}`;
  const id = `tok_${crypto.randomUUID()}`;

  const db = createDb(env.DB);
  await db.insert(schema.enrollmentTokens).values({
    id,
    token,
    orgId: body.org_id,
    expiresAt,
  });

  return new Response(
    JSON.stringify({
      token,
      org_id: body.org_id,
      expires_at: expiresAt,
      expires_in_hours: ttlHours,
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

  return new Response(
    JSON.stringify({
      status: 'ok',
      version: '0.2.0',
      stats: {
        agents_active: activeAgents.length,
        agents_revoked: revokedAgents.length,
        tokens_available: unusedTokens.length,
        tokens_total: tokens.length,
      },
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}
