import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb, seedAgent, generateEd25519Keypair, signPayload } from './helpers';

const DB = env.DB;

describe('POST /v1/agents/rekey', () => {
  let agentId: string;
  let privateKey: CryptoKey;

  beforeEach(async () => {
    await initDb(DB);
    const kp = await generateEd25519Keypair();
    privateKey = kp.privateKey;
    const seeded = await seedAgent(DB, kp.publicKeyBase64);
    agentId = seeded.agent_id;
  });

  it('should rekey agent and allow auth with new key', async () => {
    // Generate a new keypair for rekeying
    const newKp = await generateEd25519Keypair();

    const body = JSON.stringify({ new_public_key: newKp.publicKeyBase64 });
    const signature = await signPayload(privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/rekey', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': agentId,
          'X-Attestation-Signature': signature,
        },
        body,
      }),
      { DB } as any,
    );

    expect(res.status).toBe(200);
    const result = await res.json<any>();
    expect(result.ok).toBe(true);
    expect(result.key_id).toMatch(/^key_/);

    // Verify the new key works for subsequent requests (heartbeat)
    const heartbeatBody = JSON.stringify({
      device_id: 'dev_test',
      agent_id: agentId,
      timestamp: new Date().toISOString(),
    });
    const newSignature = await signPayload(newKp.privateKey, heartbeatBody);

    const heartbeatRes = await worker.fetch(
      new Request('http://localhost/v1/heartbeat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': agentId,
          'X-Attestation-Signature': newSignature,
        },
        body: heartbeatBody,
      }),
      { DB } as any,
    );

    expect(heartbeatRes.status).toBe(200);

    // Verify old key no longer works
    const oldSignature = await signPayload(privateKey, heartbeatBody);
    const oldKeyRes = await worker.fetch(
      new Request('http://localhost/v1/heartbeat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': agentId,
          'X-Attestation-Signature': oldSignature,
        },
        body: heartbeatBody,
      }),
      { DB } as any,
    );

    expect(oldKeyRes.status).toBe(401);
  });

  it('should reject rekey for revoked agent', async () => {
    const revokedKp = await generateEd25519Keypair();
    const seeded = await seedAgent(DB, revokedKp.publicKeyBase64, { status: 'revoked' });

    const newKp = await generateEd25519Keypair();
    const body = JSON.stringify({ new_public_key: newKp.publicKeyBase64 });
    const signature = await signPayload(revokedKp.privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/rekey', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': seeded.agent_id,
          'X-Attestation-Signature': signature,
        },
        body,
      }),
      { DB } as any,
    );

    expect(res.status).toBe(403);
    const result = await res.json<any>();
    expect(result.error.code).toBe('AGENT_REVOKED');
  });

  it('should reject rekey with bad signature', async () => {
    const newKp = await generateEd25519Keypair();
    const body = JSON.stringify({ new_public_key: newKp.publicKeyBase64 });
    // Sign with the wrong key (new key instead of current key)
    const badSignature = await signPayload(newKp.privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/rekey', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': agentId,
          'X-Attestation-Signature': badSignature,
        },
        body,
      }),
      { DB } as any,
    );

    expect(res.status).toBe(401);
    const result = await res.json<any>();
    expect(result.error.code).toBe('INVALID_SIGNATURE');
  });
});
