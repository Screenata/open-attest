import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import {
  initDb,
  seedAgent,
  seedAdminKey,
  generateEd25519Keypair,
  signPayload,
} from './helpers';

const DB = env.DB;
const ADMIN_SECRET = (env as any).ADMIN_SECRET ?? 'dev-secret-change-me';

async function seedRelease(d1: D1Database, opts: {
  version: string;
  channel?: 'stable' | 'beta';
  rolloutPercent?: number;
  assets?: Record<string, { url: string; sig_url: string; sha256: string }>;
}) {
  await d1
    .prepare(
      `INSERT INTO releases (version, channel, published_at, rollout_percent, notes, assets_json)
       VALUES (?, ?, ?, ?, NULL, ?)`,
    )
    .bind(
      opts.version,
      opts.channel ?? 'stable',
      new Date().toISOString(),
      opts.rolloutPercent ?? 100,
      JSON.stringify(
        opts.assets ?? {
          'aarch64-apple-darwin': {
            url: `https://github.example/${opts.version}/bin`,
            sig_url: `https://github.example/${opts.version}/bin.sig`,
            sha256: 'a'.repeat(64),
          },
        },
      ),
    )
    .run();
}

async function setAgentVersion(d1: D1Database, agentId: string, version: string, triple: string) {
  await d1
    .prepare('UPDATE agents SET current_version = ?, target_triple = ? WHERE agent_id = ?')
    .bind(version, triple, agentId)
    .run();
}

describe('update_offer wiring on heartbeat', () => {
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
    await setAgentVersion(DB, agentId, '0.5.0', 'aarch64-apple-darwin');
  });

  async function postHeartbeat() {
    const timestamp = new Date().toISOString();
    const payload = { device_id: deviceId, agent_id: agentId, timestamp };
    const body = JSON.stringify(payload);
    const signature = await signPayload(privateKey, body);
    return worker.fetch(
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
  }

  it('omits update_offer when no releases exist', async () => {
    const res = await postHeartbeat();
    const result = await res.json<any>();
    expect(result.update_offer).toBeUndefined();
  });

  it('returns an offer for a newer release', async () => {
    await seedRelease(DB, { version: '0.6.0', rolloutPercent: 100 });
    const res = await postHeartbeat();
    const result = await res.json<any>();
    expect(result.update_offer).toBeDefined();
    expect(result.update_offer.version).toBe('0.6.0');
    expect(result.update_offer.target_triple).toBe('aarch64-apple-darwin');
    expect(result.update_offer.url).toContain('0.6.0');
  });

  it('does not offer when device is already at the version', async () => {
    await seedRelease(DB, { version: '0.6.0' });
    await setAgentVersion(DB, agentId, '0.6.0', 'aarch64-apple-darwin');
    const res = await postHeartbeat();
    const result = await res.json<any>();
    expect(result.update_offer).toBeUndefined();
  });

  it('respects paused channel', async () => {
    await seedRelease(DB, { version: '0.6.0' });
    await DB.prepare("UPDATE agents SET update_channel = 'paused' WHERE agent_id = ?")
      .bind(agentId)
      .run();
    const res = await postHeartbeat();
    const result = await res.json<any>();
    expect(result.update_offer).toBeUndefined();
  });
});

describe('admin: releases endpoints', () => {
  let agentId: string;

  beforeEach(async () => {
    await initDb(DB);
    await seedAdminKey(DB, 'oak_testkey', 'org-1');
    const kp = await generateEd25519Keypair();
    const seeded = await seedAgent(DB, kp.publicKeyBase64);
    agentId = seeded.agent_id;
  });

  it('GET /v1/admin/releases lists cached releases', async () => {
    await seedRelease(DB, { version: '0.6.0' });
    await seedRelease(DB, { version: '0.7.0', channel: 'beta' });
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/releases', {
        headers: { Authorization: `Bearer ${ADMIN_SECRET}` },
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(200);
    const result = await res.json<any>();
    expect(result.releases.length).toBe(2);
    const versions = result.releases.map((r: any) => r.version).sort();
    expect(versions).toEqual(['0.6.0', '0.7.0']);
  });

  it('PATCH /v1/admin/releases/:version updates rollout_percent', async () => {
    await seedRelease(DB, { version: '0.6.0', rolloutPercent: 100 });
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/releases/0.6.0', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ rollout_percent: 25 }),
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(200);
    const row = await DB.prepare('SELECT rollout_percent FROM releases WHERE version = ?')
      .bind('0.6.0')
      .first<{ rollout_percent: number }>();
    expect(row?.rollout_percent).toBe(25);
  });

  it('PATCH rejects out-of-range rollout_percent', async () => {
    await seedRelease(DB, { version: '0.6.0' });
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/releases/0.6.0', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ rollout_percent: 150 }),
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(400);
  });

  it('PATCH /v1/admin/devices/:agent_id/update sets pin and channel', async () => {
    const res = await worker.fetch(
      new Request(`http://localhost/v1/admin/devices/${agentId}/update`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ target_version: '0.6.0', update_channel: 'beta' }),
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(200);
    const row = await DB.prepare(
      'SELECT target_version, update_channel FROM agents WHERE agent_id = ?',
    )
      .bind(agentId)
      .first<{ target_version: string; update_channel: string }>();
    expect(row?.target_version).toBe('0.6.0');
    expect(row?.update_channel).toBe('beta');
  });

  it('PATCH rejects invalid update_channel', async () => {
    const res = await worker.fetch(
      new Request(`http://localhost/v1/admin/devices/${agentId}/update`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ update_channel: 'nightly' }),
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(400);
  });

  it('admin endpoints reject without bearer secret', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/releases'),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(403);
  });
});
