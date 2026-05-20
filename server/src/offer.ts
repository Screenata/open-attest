// Glue: load releases from D1 and shape them into pickOffer's input.
//
// Kept separate from updater.ts so that file can stay pure / synchronous /
// trivially unit-testable.

import { listReleases } from './db';
import type { DB } from './db';
import type { AgentRow, UpdateOffer, ReleaseAssets } from './types';
import { pickOffer, type ReleaseSummary } from './updater';

export async function loadReleaseSummaries(db: DB): Promise<ReleaseSummary[]> {
  const rows = await listReleases(db);
  return rows
    .map((r): ReleaseSummary | null => {
      let assets: ReleaseAssets;
      try {
        assets = JSON.parse(r.assetsJson) as ReleaseAssets;
      } catch {
        return null;
      }
      if (r.channel !== 'stable' && r.channel !== 'beta') return null;
      return {
        version: r.version,
        channel: r.channel,
        publishedAt: r.publishedAt,
        rolloutPercent: r.rolloutPercent,
        assets,
      };
    })
    .filter((r): r is ReleaseSummary => r !== null);
}

export async function offerForAgent(
  db: DB,
  agent: AgentRow,
): Promise<UpdateOffer | null> {
  const releases = await loadReleaseSummaries(db);
  return pickOffer(agent, releases);
}
