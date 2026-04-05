import { apiError } from '../errors';
import { createDb, getTokenByValue, insertAgent, incrementTokenUseCount, getAgentByHardwareUuid } from '../db';
import { EnrollmentRequest, EnrollmentResponse, Env } from '../types';
import { eq } from 'drizzle-orm';
import * as schema from '../schema';

export async function handleEnroll(request: Request, env: Env): Promise<Response> {
  let body: EnrollmentRequest;
  try {
    body = await request.json<EnrollmentRequest>();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.token || !body.public_key || !body.platform || !body.hostname) {
    return apiError('VALIDATION_ERROR', 'Missing required fields: token, public_key, platform, hostname');
  }

  const validPlatforms = ['macos', 'windows', 'linux'];
  if (!validPlatforms.includes(body.platform)) {
    return apiError('VALIDATION_ERROR', 'Invalid platform');
  }

  const db = createDb(env.DB);

  const token = await getTokenByValue(db, body.token);
  if (!token) {
    return apiError('NOT_FOUND', 'Enrollment token not found');
  }

  if (token.revoked) {
    return apiError('FORBIDDEN', 'Enrollment token has been revoked');
  }

  if (token.useCount >= token.maxUses) {
    return apiError('TOKEN_ALREADY_USED', 'Enrollment token has reached its usage limit');
  }

  const now = new Date().toISOString();
  if (new Date(token.expiresAt) < new Date(now)) {
    return apiError('TOKEN_EXPIRED', 'Enrollment token has expired');
  }

  const hwUuid = body.identity_anchors?.hardware_uuid;
  const keyId = `key_${crypto.randomUUID()}`;

  // Re-enrollment: if same hardware UUID exists (active or revoked), update in-place
  if (hwUuid) {
    const existing = await getAgentByHardwareUuid(db, hwUuid);
    if (existing) {
      // Update the existing agent with new key, keep same agent_id and device_id
      await db.update(schema.agents).set({
        publicKey: body.public_key,
        keyId,
        hostname: body.hostname,
        platform: body.platform,
        platformVersion: body.platform_version || '',
        status: 'active',
        lastSeenAt: now,
      }).where(eq(schema.agents.agentId, existing.agentId));

      await incrementTokenUseCount(db, token.id, token.useCount, token.maxUses);

      const response: EnrollmentResponse = {
        agent_id: existing.agentId,
        key_id: keyId,
        org_id: existing.orgId,
        config: {
          heartbeat_interval_seconds: 300,
          snapshot_interval_seconds: 3600,
        },
      };
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // New enrollment
  const agentId = `agent_${crypto.randomUUID()}`;
  const deviceId = hwUuid ? `dev_${hwUuid}` : `dev_${crypto.randomUUID()}`;

  await insertAgent(db, {
    agentId,
    orgId: token.orgId,
    publicKey: body.public_key,
    keyId,
    hostname: body.hostname,
    platform: body.platform,
    platformVersion: body.platform_version || '',
    deviceId,
    hardwareUuid: hwUuid,
  });

  await incrementTokenUseCount(db, token.id, token.useCount, token.maxUses);

  const response: EnrollmentResponse = {
    agent_id: agentId,
    key_id: keyId,
    org_id: token.orgId,
    config: {
      heartbeat_interval_seconds: 300,
      snapshot_interval_seconds: 3600,
    },
  };

  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
