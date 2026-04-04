import { authenticateAdmin } from '../auth';
import { apiError } from '../errors';
import { createDb, listDevices, getDeviceByDeviceId, getDeviceChecks } from '../db';
import type { Env, AgentRow, DeviceCheckRow } from '../types';

function agentToDevice(a: AgentRow) {
  return {
    agent_id: a.agentId,
    org_id: a.orgId,
    public_key: a.publicKey,
    key_id: a.keyId,
    hostname: a.hostname,
    platform: a.platform,
    platform_version: a.platformVersion,
    device_id: a.deviceId,
    status: a.status,
    enrolled_at: a.enrolledAt,
    last_seen_at: a.lastSeenAt,
  };
}

function checkToWire(c: DeviceCheckRow) {
  return {
    device_id: c.deviceId,
    check_key: c.checkKey,
    check_value: JSON.parse(c.checkValue),
    observed_at: c.observedAt,
    source: c.source,
  };
}

export async function handleListDevices(request: Request, env: Env): Promise<Response> {
  const db = createDb(env.DB);

  const authResult = await authenticateAdmin(request, db, env);
  if (authResult instanceof Response) {
    return authResult;
  }

  const url = new URL(request.url);
  let limit = parseInt(url.searchParams.get('limit') || '50', 10);
  if (isNaN(limit) || limit < 1) limit = 50;
  if (limit > 200) limit = 200;

  const cursorParam = url.searchParams.get('cursor');
  let cursor: string | undefined;
  if (cursorParam) {
    try {
      cursor = atob(cursorParam);
    } catch {
      return apiError('INVALID_REQUEST', 'Invalid cursor');
    }
  }

  const result = await listDevices(db, limit, cursor);

  return new Response(
    JSON.stringify({
      devices: result.devices.map(agentToDevice),
      next_cursor: result.next_cursor,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

export async function handleGetDevice(request: Request, env: Env, deviceId: string): Promise<Response> {
  const db = createDb(env.DB);

  const authResult = await authenticateAdmin(request, db, env);
  if (authResult instanceof Response) {
    return authResult;
  }

  const device = await getDeviceByDeviceId(db, deviceId);
  if (!device) {
    return apiError('NOT_FOUND', 'Device not found');
  }

  const checks = await getDeviceChecks(db, deviceId);

  return new Response(
    JSON.stringify({
      device: agentToDevice(device),
      checks: checks.map(checkToWire),
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
