import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb, seedToken, generateEd25519Keypair } from './helpers';

const DB = env.DB;

describe('POST /v1/agents/enroll', () => {
  beforeEach(async () => {
    await initDb(DB);
  });

  it('should enroll an agent with a valid token', async () => {
    const { token, org_id } = await seedToken(DB);
    const { publicKeyBase64 } = await generateEd25519Keypair();

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          public_key: publicKeyBase64,
          hostname: 'test-machine',
          platform: 'macos',
          platform_version: '14.0',
          identity_anchors: { hardware_uuid: 'test-uuid' },
        }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.agent_id).toMatch(/^agent_/);
    expect(body.key_id).toMatch(/^key_/);
    expect(body.org_id).toBe(org_id);
    expect(body.config.heartbeat_interval_seconds).toBe(300);
    expect(body.config.snapshot_interval_seconds).toBe(3600);
  });

  it('should reject an expired token', async () => {
    const { token } = await seedToken(DB, {
      expires_at: new Date(Date.now() - 3600_000).toISOString(),
    });
    const { publicKeyBase64 } = await generateEd25519Keypair();

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          public_key: publicKeyBase64,
          hostname: 'test-machine',
          platform: 'macos',
          platform_version: '14.0',
          identity_anchors: {},
        }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(400);
    const body = await res.json<any>();
    expect(body.error.code).toBe('TOKEN_EXPIRED');
  });

  it('should reject a used token', async () => {
    const { token } = await seedToken(DB, { used: 1 });
    const { publicKeyBase64 } = await generateEd25519Keypair();

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          public_key: publicKeyBase64,
          hostname: 'test-machine',
          platform: 'macos',
          platform_version: '14.0',
          identity_anchors: {},
        }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(400);
    const body = await res.json<any>();
    expect(body.error.code).toBe('TOKEN_ALREADY_USED');
  });

  it('should reject a revoked token', async () => {
    const { token } = await seedToken(DB, { revoked: 1 });
    const { publicKeyBase64 } = await generateEd25519Keypair();

    const res = await worker.fetch(
      new Request('http://localhost/v1/agents/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          public_key: publicKeyBase64,
          hostname: 'test-machine',
          platform: 'macos',
          platform_version: '14.0',
          identity_anchors: {},
        }),
      }),
      { DB } as any,
    );

    expect(res.status).toBe(403);
    const body = await res.json<any>();
    expect(body.error.code).toBe('FORBIDDEN');
  });
});
