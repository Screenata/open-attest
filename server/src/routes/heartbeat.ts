import { authenticateAgent } from '../auth';
import { apiError } from '../errors';
import { createDb, updateLastSeen } from '../db';
import { HeartbeatPayload, Env } from '../types';

export async function handleHeartbeat(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.arrayBuffer();
  const bodyBytes = new Uint8Array(rawBody);

  const db = createDb(env.DB);

  const authResult = await authenticateAgent(request, bodyBytes, db);
  if (authResult instanceof Response) {
    return authResult;
  }
  const { agent } = authResult;

  let payload: HeartbeatPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(bodyBytes)) as HeartbeatPayload;
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!payload.timestamp) {
    return apiError('VALIDATION_ERROR', 'Missing required field: timestamp');
  }

  await updateLastSeen(db, agent.agentId, payload.timestamp);

  return new Response(
    JSON.stringify({
      ok: true,
      config: {
        snapshot_interval_seconds: 3600,
        heartbeat_interval_seconds: 300,
      },
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
