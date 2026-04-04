import { authenticateAdmin } from '../auth';
import { apiError } from '../errors';
import { createDb, getAgent, revokeAgent } from '../db';
import { Env } from '../types';

export async function handleRevoke(request: Request, env: Env): Promise<Response> {
  const db = createDb(env.DB);

  const authResult = await authenticateAdmin(request, db, env);
  if (authResult instanceof Response) {
    return authResult;
  }

  let body: { agent_id: string };
  try {
    body = await request.json<{ agent_id: string }>();
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!body.agent_id) {
    return apiError('VALIDATION_ERROR', 'Missing required field: agent_id');
  }

  const agent = await getAgent(db, body.agent_id);
  if (!agent) {
    return apiError('NOT_FOUND', 'Agent not found');
  }

  await revokeAgent(db, body.agent_id);

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
