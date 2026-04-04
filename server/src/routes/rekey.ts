import { authenticateAgent } from '../auth';
import { apiError } from '../errors';
import { createDb, rekeyAgent } from '../db';
import { Env } from '../types';

export async function handleRekey(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.arrayBuffer();
  const bodyBytes = new Uint8Array(rawBody);

  const db = createDb(env.DB);

  const authResult = await authenticateAgent(request, bodyBytes, db);
  if (authResult instanceof Response) {
    return authResult;
  }
  const { agent } = authResult;

  let body: { new_public_key?: string };
  try {
    body = JSON.parse(new TextDecoder().decode(bodyBytes));
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.new_public_key) {
    return apiError('VALIDATION_ERROR', 'Missing required field: new_public_key');
  }

  const newKeyId = `key_${crypto.randomUUID()}`;
  await rekeyAgent(db, agent.agentId, body.new_public_key, newKeyId);

  return new Response(
    JSON.stringify({
      ok: true,
      key_id: newKeyId,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
