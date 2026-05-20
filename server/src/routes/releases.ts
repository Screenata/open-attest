// Admin-only endpoints for the cached release manifest and per-device
// update controls. Bearer-secret-authenticated like the other admin routes.

import { apiError } from '../errors';
import {
  createDb,
  listReleases,
  setReleaseRollout,
  setAgentUpdateControls,
  getAgent,
} from '../db';
import { pollReleases } from '../cron/poll-releases';
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

// GET /v1/admin/releases — list cached releases (admin UI consumes this)
export async function handleListReleases(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;
  const db = createDb(env.DB);
  const rows = await listReleases(db);
  return new Response(
    JSON.stringify({
      releases: rows.map((r) => ({
        version: r.version,
        channel: r.channel,
        published_at: r.publishedAt,
        rollout_percent: r.rolloutPercent,
        notes: r.notes,
        fetched_at: r.fetchedAt,
        // Show triples we have assets for so admins can sanity-check the asset set.
        targets: Object.keys(JSON.parse(r.assetsJson) as Record<string, unknown>).sort(),
      })),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

// POST /v1/admin/releases/refresh — trigger an immediate poll
export async function handleRefreshReleases(request: Request, env: Env): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;
  const db = createDb(env.DB);
  const result = await pollReleases(db);
  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// PATCH /v1/admin/releases/:version — update rollout_percent
export async function handlePatchRelease(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  let body: { rollout_percent?: number };
  try {
    body = await request.json();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }
  if (
    typeof body.rollout_percent !== 'number' ||
    !Number.isInteger(body.rollout_percent) ||
    body.rollout_percent < 0 ||
    body.rollout_percent > 100
  ) {
    return apiError('VALIDATION_ERROR', 'rollout_percent must be an integer 0..100');
  }

  const db = createDb(env.DB);
  await setReleaseRollout(db, version, body.rollout_percent);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// PATCH /v1/admin/devices/:agent_id/update — set target_version / channel
export async function handlePatchDeviceUpdate(
  request: Request,
  env: Env,
  agentId: string,
): Promise<Response> {
  const authErr = authenticateSecret(request, env);
  if (authErr) return authErr;

  let body: {
    target_version?: string | null;
    update_channel?: 'stable' | 'beta' | 'paused';
  };
  try {
    body = await request.json();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (
    body.update_channel !== undefined &&
    !['stable', 'beta', 'paused'].includes(body.update_channel)
  ) {
    return apiError('VALIDATION_ERROR', "update_channel must be 'stable' | 'beta' | 'paused'");
  }

  const db = createDb(env.DB);
  if (!(await getAgent(db, agentId))) {
    return apiError('NOT_FOUND', 'Agent not found');
  }
  await setAgentUpdateControls(db, agentId, {
    targetVersion: body.target_version === undefined ? undefined : body.target_version,
    updateChannel: body.update_channel,
  });
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
