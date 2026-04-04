import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb, seedAgent, generateEd25519Keypair, signPayload } from './helpers';

const DB = env.DB;

describe('POST /v1/heartbeat', () => {
  let agentId: string;
  let deviceId: string;
  let privateKey: CryptoKey;

  beforeEach(async () => {
    await initDb(DB);
    const kp = await generateEd25519Keypair();
    privateKey = kp.privateKey;
    const seeded = await seedAgent(DB, kp.publicKeyBase64);
    agentId = seeded.agent_id;
    deviceId = seeded.device_id;
  });

  it('should update last_seen and return config', async () => {
    const timestamp = new Date().toISOString();
    const payload = { device_id: deviceId, agent_id: agentId, timestamp };
    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/heartbeat', {
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
    expect(result.config.heartbeat_interval_seconds).toBe(300);
    expect(result.config.snapshot_interval_seconds).toBe(3600);

    // Verify last_seen_at was updated
    const agent = await DB.prepare('SELECT last_seen_at FROM agents WHERE agent_id = ?')
      .bind(agentId)
      .first<{ last_seen_at: string }>();
    expect(agent?.last_seen_at).toBe(timestamp);
  });
});
