import { authenticateAgent, authenticateAdmin } from '../auth';
import { apiError } from '../errors';
import {
  createDb,
  insertAttestation,
  upsertDeviceCheck,
  getAttestation,
  updateLastSeen,
  updateAgentDeviceInfo,
  recordAgentVersion,
  getAgent,
} from '../db';
import { AttestationPayload, Env } from '../types';
import { offerForAgent } from '../offer';

export async function handlePostAttestation(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.arrayBuffer();
  const bodyBytes = new Uint8Array(rawBody);

  const db = createDb(env.DB);

  const authResult = await authenticateAgent(request, bodyBytes, db);
  if (authResult instanceof Response) {
    return authResult;
  }
  const { agent } = authResult;

  let payload: AttestationPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(bodyBytes)) as AttestationPayload;
  } catch {
    return apiError('INVALID_REQUEST', 'Invalid JSON body');
  }

  if (!payload.attestation_id || !payload.schema_version || !payload.collected_at || !payload.checks) {
    return apiError('VALIDATION_ERROR', 'Missing required fields');
  }

  const signature = request.headers.get('X-Attestation-Signature')!;

  await insertAttestation(db, {
    attestationId: payload.attestation_id,
    agentId: agent.agentId,
    deviceId: agent.deviceId!,
    schemaVersion: payload.schema_version,
    collectedAt: payload.collected_at,
    payload: new TextDecoder().decode(bodyBytes),
    signature,
  });

  await updateLastSeen(db, agent.agentId, payload.collected_at);

  // Refresh mutable device metadata reported by the agent. Skip blank/whitespace
  // values so a misbehaving collector can't blank out a column. Only write fields
  // that actually changed to keep the update a no-op when nothing drifted.
  const reportedHostname = payload.device?.hostname?.trim();
  const reportedPlatform = payload.device?.platform?.trim();
  const reportedPlatformVersion = payload.device?.platform_version?.trim();
  const drift: { hostname?: string; platform?: string; platformVersion?: string } = {};
  if (reportedHostname && reportedHostname !== agent.hostname) {
    drift.hostname = reportedHostname;
  }
  if (reportedPlatform && reportedPlatform !== agent.platform) {
    drift.platform = reportedPlatform;
  }
  if (reportedPlatformVersion && reportedPlatformVersion !== agent.platformVersion) {
    drift.platformVersion = reportedPlatformVersion;
  }
  if (Object.keys(drift).length > 0) {
    await updateAgentDeviceInfo(db, agent.agentId, drift);
  }

  for (const check of payload.checks) {
    await upsertDeviceCheck(db, {
      deviceId: agent.deviceId!,
      checkKey: check.key,
      checkValue: JSON.stringify(check.value),
      observedAt: check.observed_at,
      source: check.source,
    });
  }

  // Persist updater-relevant fields. version/target_triple come from the
  // agent payload — server is the source of truth for what each device
  // reports it's running.
  const reportedVersion = payload.agent?.version?.trim();
  const reportedTriple = payload.agent?.target_triple?.trim();
  const versionFields: { currentVersion?: string; targetTriple?: string } = {};
  if (reportedVersion && reportedVersion !== agent.currentVersion) {
    versionFields.currentVersion = reportedVersion;
  }
  if (reportedTriple && reportedTriple !== agent.targetTriple) {
    versionFields.targetTriple = reportedTriple;
  }
  if (Object.keys(versionFields).length > 0) {
    await recordAgentVersion(db, agent.agentId, versionFields);
  }

  const refreshed = await getAgent(db, agent.agentId);
  const updateOffer = refreshed ? await offerForAgent(db, refreshed) : null;

  return new Response(
    JSON.stringify({
      ok: true,
      config: {
        snapshot_interval_seconds: 3600,
        heartbeat_interval_seconds: 300,
      },
      ...(updateOffer ? { update_offer: updateOffer } : {}),
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

export async function handleGetAttestation(request: Request, env: Env, attestationId: string): Promise<Response> {
  const db = createDb(env.DB);

  const authResult = await authenticateAdmin(request, db, env);
  if (authResult instanceof Response) {
    return authResult;
  }

  const attestation = await getAttestation(db, attestationId);
  if (!attestation) {
    return apiError('NOT_FOUND', 'Attestation not found');
  }

  return new Response(
    JSON.stringify({
      attestation_id: attestation.attestationId,
      agent_id: attestation.agentId,
      device_id: attestation.deviceId,
      schema_version: attestation.schemaVersion,
      collected_at: attestation.collectedAt,
      signature: attestation.signature,
      created_at: attestation.createdAt,
      payload: JSON.parse(attestation.payload),
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
