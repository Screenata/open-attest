import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb, seedAgent, seedAdminKey, generateEd25519Keypair, signPayload } from './helpers';

const DB = env.DB;
const ADMIN_KEY = 'test-admin-key-12345';

describe('POST /v1/attestations', () => {
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
    await seedAdminKey(DB, ADMIN_KEY, seeded.org_id);
  });

  it('should store a valid attestation', async () => {
    const payload = {
      schema_version: '0.1',
      attestation_id: `att_${crypto.randomUUID()}`,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: agentId },
      device: {
        device_id: deviceId,
        hostname: 'test-host',
        platform: 'macos',
        platform_version: '14.0',
        identity_anchors: {},
      },
      checks: [
        {
          key: 'disk_encryption',
          value: { type: 'bool', value: true },
          observed_at: new Date().toISOString(),
          source: 'system',
        },
      ],
    };

    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/attestations', {
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
  });

  it('should reject a bad signature', async () => {
    const payload = {
      schema_version: '0.1',
      attestation_id: `att_${crypto.randomUUID()}`,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: agentId },
      device: { device_id: deviceId, hostname: 'test-host', platform: 'macos', platform_version: '14.0', identity_anchors: {} },
      checks: [],
    };
    const body = JSON.stringify(payload);

    const res = await worker.fetch(
      new Request('http://localhost/v1/attestations', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': agentId,
          'X-Attestation-Signature': btoa('invalidsignaturebytes1234567890ab'),
        },
        body,
      }),
      { DB } as any,
    );

    expect(res.status).toBe(401);
    const result = await res.json<any>();
    expect(result.error.code).toBe('INVALID_SIGNATURE');
  });

  it('should refresh hostname, platform, and platform_version when the attestation reports new values', async () => {
    // seedAgent stores hostname='test-host', platform='macos', platform_version='14.0'.
    // Send an attestation with all three changed and verify the row is updated.
    const payload = {
      schema_version: '0.1',
      attestation_id: `att_${crypto.randomUUID()}`,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: agentId },
      device: {
        device_id: deviceId,
        hostname: 'taohuang-mbp',
        platform: 'macos',
        platform_version: '14.6.1',
        identity_anchors: {},
      },
      checks: [],
    };
    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/attestations', {
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

    const row = await DB
      .prepare('SELECT hostname, platform, platform_version FROM agents WHERE agent_id = ?')
      .bind(agentId)
      .first<{ hostname: string; platform: string; platform_version: string }>();
    expect(row?.hostname).toBe('taohuang-mbp');
    expect(row?.platform).toBe('macos');
    expect(row?.platform_version).toBe('14.6.1');
  });

  it('should not overwrite device fields when the attestation omits or blanks them', async () => {
    // Empty/whitespace values should be ignored — keep what's already there.
    const payload = {
      schema_version: '0.1',
      attestation_id: `att_${crypto.randomUUID()}`,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: agentId },
      device: {
        device_id: deviceId,
        hostname: '   ',
        platform: '',
        platform_version: '   ',
        identity_anchors: {},
      },
      checks: [],
    };
    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/attestations', {
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

    const row = await DB
      .prepare('SELECT hostname, platform, platform_version FROM agents WHERE agent_id = ?')
      .bind(agentId)
      .first<{ hostname: string; platform: string; platform_version: string }>();
    expect(row?.hostname).toBe('test-host');
    expect(row?.platform).toBe('macos');
    expect(row?.platform_version).toBe('14.0');
  });

  it('should refresh only platform_version when only that field drifts', async () => {
    // Partial drift — only the OS got upgraded since enrollment.
    const payload = {
      schema_version: '0.1',
      attestation_id: `att_${crypto.randomUUID()}`,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: agentId },
      device: {
        device_id: deviceId,
        hostname: 'test-host',
        platform: 'macos',
        platform_version: '15.1',
        identity_anchors: {},
      },
      checks: [],
    };
    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/attestations', {
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

    const row = await DB
      .prepare('SELECT hostname, platform_version FROM agents WHERE agent_id = ?')
      .bind(agentId)
      .first<{ hostname: string; platform_version: string }>();
    expect(row?.hostname).toBe('test-host');
    expect(row?.platform_version).toBe('15.1');
  });

  it('should reject a revoked agent', async () => {
    const kp2 = await generateEd25519Keypair();
    const revokedAgent = await seedAgent(DB, kp2.publicKeyBase64, { status: 'revoked' });

    const payload = {
      schema_version: '0.1',
      attestation_id: `att_${crypto.randomUUID()}`,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: revokedAgent.agent_id },
      device: { device_id: revokedAgent.device_id, hostname: 'test', platform: 'macos', platform_version: '14.0', identity_anchors: {} },
      checks: [],
    };
    const body = JSON.stringify(payload);
    const signature = await signPayload(kp2.privateKey, body);

    const res = await worker.fetch(
      new Request('http://localhost/v1/attestations', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Id': revokedAgent.agent_id,
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
});

describe('GET /v1/attestations/:id', () => {
  let agentId: string;
  let deviceId: string;
  let privateKey: CryptoKey;
  let orgId: string;

  beforeEach(async () => {
    await initDb(DB);
    const kp = await generateEd25519Keypair();
    privateKey = kp.privateKey;
    const seeded = await seedAgent(DB, kp.publicKeyBase64);
    agentId = seeded.agent_id;
    deviceId = seeded.device_id;
    orgId = seeded.org_id;
    await seedAdminKey(DB, ADMIN_KEY, orgId);
  });

  it('should retrieve an attestation by ID', async () => {
    const attestationId = `att_${crypto.randomUUID()}`;
    const payload = {
      schema_version: '0.1',
      attestation_id: attestationId,
      collected_at: new Date().toISOString(),
      agent: { name: 'open-attest', version: '0.1', agent_id: agentId },
      device: { device_id: deviceId, hostname: 'test', platform: 'macos', platform_version: '14.0', identity_anchors: {} },
      checks: [],
    };
    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);

    // First, submit the attestation
    await worker.fetch(
      new Request('http://localhost/v1/attestations', {
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

    // Then, retrieve it
    const res = await worker.fetch(
      new Request(`http://localhost/v1/attestations/${attestationId}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      }),
      { DB } as any,
    );

    expect(res.status).toBe(200);
    const result = await res.json<any>();
    expect(result.attestation_id).toBe(attestationId);
    expect(result.payload.schema_version).toBe('0.1');
  });
});
