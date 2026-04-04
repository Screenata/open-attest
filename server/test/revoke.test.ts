import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb, seedAgent, seedAdminKey, generateEd25519Keypair, signPayload } from './helpers';

const DB = env.DB;
const ADMIN_KEY = 'test-admin-key-revoke';

describe('POST /v1/agents/revoke', () => {
  let agentId: string;
  let orgId: string;
  let privateKey: CryptoKey;
  let deviceId: string;

  beforeEach(async () => {
    await initDb(DB);
    orgId = `org_${crypto.randomUUID()}`;
    await seedAdminKey(DB, ADMIN_KEY, orgId);

    const kp = await generateEd25519Keypair();
    privateKey = kp.privateKey;
    const seeded = await seedAgent(DB, kp.publicKeyBase64, { org_id: orgId });
    agentId = seeded.agent_id;
    deviceId = seeded.device_id;
  });

  it('should revoke an agent', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify({ agent_id: agentId }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.ok).toBe(true);

    // Verify the agent is now revoked - heartbeat should fail
    const hbPayload = { device_id: deviceId, agent_id: agentId, timestamp: new Date().toISOString() };
    const hbBody = JSON.stringify(hbPayload);
    const signature = await signPayload(privateKey, hbBody);

    const hbRes = await worker.fetch(
      new Request('http://localhost/v1/heartbeat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': agentId,
          'X-Attestation-Signature': signature,
        },
        body: hbBody,
      }),
      { DB } as any,
    );

    expect(hbRes.status).toBe(403);
    const hbResult = await hbRes.json<any>();
    expect(hbResult.error.code).toBe('AGENT_REVOKED');
  });

  it('should return 404 for unknown agent', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify({ agent_id: 'agent_nonexistent' }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(404);
  });

  it('should reject without auth', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: agentId }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(403);
  });
});
