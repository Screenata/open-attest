import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { initDb } from './helpers';

const DB = env.DB;
const ADMIN_SECRET = 'dev-secret-change-me';

describe('POST /v1/admin/api-keys', () => {
  beforeEach(async () => {
    await initDb(DB);
  });

  it('should create an API key', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ org_id: 'org_test', label: 'my key' }),
      }),
      { DB, ADMIN_SECRET } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.api_key).toMatch(/^oak_/);
    expect(body.org_id).toBe('org_test');
    expect(body.label).toBe('my key');

    // The returned key should work for admin endpoints
    const devicesRes = await worker.fetch(
      new Request('http://localhost/v1/devices', {
        method: 'GET',
        headers: { Authorization: `Bearer ${body.api_key}` },
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(devicesRes.status).toBe(200);
  });

  it('should reject wrong secret', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer wrong-secret',
        },
        body: JSON.stringify({ org_id: 'org_test' }),
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(403);
  });

  it('should reject missing org_id', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({}),
      }),
      { DB, ADMIN_SECRET } as any,
    );
    expect(res.status).toBe(400);
  });
});

describe('POST /v1/admin/tokens', () => {
  beforeEach(async () => {
    await initDb(DB);
  });

  it('should create an enrollment token', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/tokens', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ org_id: 'org_test', expires_in_hours: 48 }),
      }),
      { DB, ADMIN_SECRET } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.token).toMatch(/^oat_/);
    expect(body.org_id).toBe('org_test');
    expect(body.expires_in_hours).toBe(48);
  });

  it('should default to 24h TTL', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/tokens', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ADMIN_SECRET}`,
        },
        body: JSON.stringify({ org_id: 'org_test' }),
      }),
      { DB, ADMIN_SECRET } as any,
    );

    const body = await res.json<any>();
    expect(body.expires_in_hours).toBe(24);
  });
});

describe('GET /v1/admin/status', () => {
  beforeEach(async () => {
    await initDb(DB);
  });

  it('should return server stats', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/v1/admin/status', {
        method: 'GET',
        headers: { Authorization: `Bearer ${ADMIN_SECRET}` },
      }),
      { DB, ADMIN_SECRET } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.status).toBe('ok');
    expect(body.stats.agents_active).toBe(0);
    expect(body.stats.tokens_available).toBe(0);
  });
});

describe('GET /', () => {
  it('should return health check', async () => {
    const res = await worker.fetch(
      new Request('http://localhost/', { method: 'GET' }),
      { DB, ADMIN_SECRET } as any,
    );

    expect(res.status).toBe(200);
    const body = await res.json<any>();
    expect(body.name).toBe('open-attest');
    expect(body.status).toBe('ok');
  });
});
