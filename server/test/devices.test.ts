import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb, seedAgent, seedAdminKey, generateEd25519Keypair } from './helpers';

const DB = env.DB;
const ADMIN_KEY = 'test-admin-key-devices';

describe('GET /v1/devices', () => {
  let orgId: string;

  beforeEach(async () => {
    await initDb(DB);
    orgId = `org_${crypto.randomUUID()}`;
    await seedAdminKey(DB, ADMIN_KEY, orgId);

    // Seed multiple agents/devices
    for (let i = 0; i < 5; i++) {
      const kp = await generateEd25519Keypair();
      await seedAgent(DB, kp.publicKeyBase64, { org_id: orgId });
    }
  });

  it('should list devices', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/devices', {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      }),
      { DB } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.devices.length).toBe(5);
  });

  it('should paginate devices', async () => {
    const res1 = await worker.fetch(
      new Request('http://localhost/v1/devices?limit=2', {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      }),
      { DB } as any,
    );

    expect(res1.status).toBe(200);
    const body1 = await res1.json<any>();
    expect(body1.devices.length).toBe(2);
    expect(body1.next_cursor).toBeTruthy();

    // Fetch next page
    const res2 = await worker.fetch(
      new Request(`http://localhost/v1/devices?limit=2&cursor=${body1.next_cursor}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      }),
      { DB } as any,
    );

    expect(res2.status).toBe(200);
    const body2 = await res2.json<any>();
    expect(body2.devices.length).toBe(2);

    // Ensure no overlap
    const ids1 = body1.devices.map((d: any) => d.device_id);
    const ids2 = body2.devices.map((d: any) => d.device_id);
    for (const id of ids2) {
      expect(ids1).not.toContain(id);
    }
  });

  it('should reject without auth', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/devices', { method: 'GET' }),
      { DB } as any,
    );

    expect(res.status).toBe(403);
  });
});

describe('GET /v1/devices/:deviceId', () => {
  let orgId: string;
  let deviceId: string;

  beforeEach(async () => {
    await initDb(DB);
    orgId = `org_${crypto.randomUUID()}`;
    await seedAdminKey(DB, ADMIN_KEY, orgId);

    const kp = await generateEd25519Keypair();
    const seeded = await seedAgent(DB, kp.publicKeyBase64, { org_id: orgId });
    deviceId = seeded.device_id;

    // Seed a device check
    await DB.prepare(
      `INSERT INTO device_checks (device_id, check_key, check_value, observed_at, source) VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(deviceId, 'disk_encryption', JSON.stringify({ type: 'bool', value: true }), new Date().toISOString(), 'system')
      .run();
  });

  it('should get device with checks', async () => {
    const res = await worker.fetch(
      new Request(`http://localhost/v1/devices/${deviceId}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      }),
      { DB } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.device.device_id).toBe(deviceId);
    expect(body.checks.length).toBe(1);
    expect(body.checks[0].check_key).toBe('disk_encryption');
    expect(body.checks[0].check_value.type).toBe('bool');
  });

  it('should return 404 for unknown device', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/devices/dev_nonexistent', {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      }),
      { DB } as any,
    );

    expect(res.status).toBe(404);
  });
});
