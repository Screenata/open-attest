import { Env } from './types';
import { apiError } from './errors';
import { handleEnroll } from './routes/enroll';
import { handleRevoke } from './routes/revoke';
import { handlePostAttestation, handleGetAttestation } from './routes/attestations';
import { handleHeartbeat } from './routes/heartbeat';
import { handleRekey } from './routes/rekey';
import { handleListDevices, handleGetDevice } from './routes/devices';
import { handleCreateApiKey, handleListApiKeys, handleDeleteApiKey, handleCreateToken, handleListTokens, handleAdminStatus } from './routes/admin';
import { handleEnrollmentPage } from './routes/enrollment-page';

export async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Root — redirect to admin UI
  if (method === 'GET' && path === '/') {
    return new Response(null, { status: 302, headers: { Location: '/admin/' } });
  }

  // Health check
  if (method === 'GET' && path === '/health') {
    return new Response(JSON.stringify({ name: 'open-attest', version: '0.3.1', status: 'ok' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // --- Admin bootstrap endpoints (ADMIN_SECRET auth) ---

  if (method === 'POST' && path === '/v1/admin/api-keys') {
    return handleCreateApiKey(request, env);
  }

  if (method === 'GET' && path === '/v1/admin/api-keys') {
    return handleListApiKeys(request, env);
  }

  if (method === 'DELETE' && path === '/v1/admin/api-keys') {
    return handleDeleteApiKey(request, env);
  }

  if (method === 'POST' && path === '/v1/admin/tokens') {
    return handleCreateToken(request, env);
  }

  if (method === 'GET' && path === '/v1/admin/tokens') {
    return handleListTokens(request, env);
  }

  if (method === 'GET' && path === '/v1/admin/status') {
    return handleAdminStatus(request, env);
  }

  // --- Enrollment page (public, no auth) ---

  const enrollPageMatch = path.match(/^\/enroll\/([^/]+)$/);
  if (method === 'GET' && enrollPageMatch) {
    return handleEnrollmentPage(request, env, enrollPageMatch[1]);
  }

  // --- Agent endpoints ---

  if (method === 'POST' && path === '/v1/agents/enroll') {
    return handleEnroll(request, env);
  }

  if (method === 'POST' && path === '/v1/agents/revoke') {
    return handleRevoke(request, env);
  }

  if (method === 'POST' && path === '/v1/agents/rekey') {
    return handleRekey(request, env);
  }

  if (method === 'POST' && path === '/v1/attestations') {
    return handlePostAttestation(request, env);
  }

  if (method === 'POST' && path === '/v1/heartbeat') {
    return handleHeartbeat(request, env);
  }

  // --- Admin read endpoints (API key auth) ---

  if (method === 'GET' && path === '/v1/devices') {
    return handleListDevices(request, env);
  }

  const deviceMatch = path.match(/^\/v1\/devices\/([^/]+)$/);
  if (method === 'GET' && deviceMatch) {
    return handleGetDevice(request, env, deviceMatch[1]);
  }

  const attestationMatch = path.match(/^\/v1\/attestations\/([^/]+)$/);
  if (method === 'GET' && attestationMatch) {
    return handleGetAttestation(request, env, attestationMatch[1]);
  }

  // SPA fallback — for /admin/* routes that aren't static files,
  // serve index.html so React Router handles client-side routing
  if (method === 'GET' && path.startsWith('/admin')) {
    if (path === '/admin') {
      return new Response(null, { status: 302, headers: { Location: '/admin/' } });
    }
    return env.ASSETS.fetch(new Request(new URL('/admin/index.html', request.url), request));
  }

  return apiError('NOT_FOUND', `No route found for ${method} ${path}`);
}
