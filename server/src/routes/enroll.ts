import { apiError } from '../errors';
import { createDb, getTokenByValue, insertAgent, markTokenUsed } from '../db';
import { EnrollmentRequest, EnrollmentResponse, Env } from '../types';

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

  if (token.used) {
    return apiError('TOKEN_ALREADY_USED', 'Enrollment token has already been used');
  }

  const now = new Date().toISOString();
  if (new Date(token.expiresAt) < new Date(now)) {
    return apiError('TOKEN_EXPIRED', 'Enrollment token has expired');
  }

  const agentId = `agent_${crypto.randomUUID()}`;
  const deviceId = `dev_${crypto.randomUUID()}`;
  const keyId = `key_${crypto.randomUUID()}`;

  await insertAgent(db, {
    agentId,
    orgId: token.orgId,
    publicKey: body.public_key,
    keyId,
    hostname: body.hostname,
    platform: body.platform,
    platformVersion: body.platform_version || '',
    deviceId,
  });

  await markTokenUsed(db, token.id);

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
