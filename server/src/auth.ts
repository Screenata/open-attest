import { verifyEd25519Signature } from './crypto';
import { apiError } from './errors';
import { getAgent, getAdminApiKey, type DB } from './db';
import type { AgentRow, Env } from './types';

export async function authenticateAgent(
  request: Request,
  body: Uint8Array,
  db: DB,
): Promise<{ agent: AgentRow } | Response> {
  const agentId = request.headers.get('X-Agent-Id');
  const signature = request.headers.get('X-Attestation-Signature');

  if (!agentId || !signature) {
    return apiError('INVALID_REQUEST', 'Missing X-Agent-Id or X-Attestation-Signature header');
  }

  const agent = await getAgent(db, agentId);

  if (!agent) {
    return apiError('NOT_FOUND', 'Agent not found');
  }

  if (agent.status === 'revoked') {
    return apiError('AGENT_REVOKED', 'Agent has been revoked');
  }

  const valid = await verifyEd25519Signature(agent.publicKey, signature, body);
  if (!valid) {
    return apiError('INVALID_SIGNATURE', 'Signature verification failed');
  }

  return { agent };
}

export async function authenticateAdmin(
  request: Request,
  db: DB,
  env?: Env,
): Promise<{ org_id: string } | Response> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return apiError('FORBIDDEN', 'Missing or invalid Authorization header');
  }

  const token = authHeader.slice(7);

  // Accept admin secret as a superuser auth method
  if (env?.ADMIN_SECRET && token === env.ADMIN_SECRET) {
    return { org_id: '*' };
  }

  // Otherwise, check API key
  const keyBytes = new TextEncoder().encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
  const hashArray = new Uint8Array(hashBuffer);
  let keyHash = '';
  for (const b of hashArray) {
    keyHash += b.toString(16).padStart(2, '0');
  }

  const row = await getAdminApiKey(db, keyHash);

  if (!row) {
    return apiError('FORBIDDEN', 'Invalid API key');
  }

  return { org_id: row.orgId };
}
