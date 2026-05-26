// Hourly poller: fetch GitHub Releases for screenata/open-attest and cache
// them in D1. Hand-shape into ReleaseSummary rows for pickOffer.
//
// The Worker has 60/hr/IP anonymous GH API budget; hourly polling burns
// ~720 requests/month, well under that. Agents never call GH directly.

import { upsertRelease, listReleases, deleteRelease, getRelease } from '../db';
import type { DB } from '../db';
import type { ReleaseAssets } from '../types';

export const GITHUB_OWNER = 'screenata';
export const GITHUB_REPO = 'open-attest';

const RELEASES_URL = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases?per_page=20`;

// Asset name pattern, e.g. "open-attest-0.6.0-aarch64-apple-darwin"
// and the companion "open-attest-0.6.0-aarch64-apple-darwin.sig".
//
// We deliberately accept any non-empty triple — adding new targets in the
// future won't require server changes.
const ASSET_RE = /^open-attest-(?<version>\d+\.\d+\.\d+)-(?<triple>[a-z0-9_-]+?)(?<ext>\.exe)?$/;

type GithubAsset = {
  name: string;
  browser_download_url: string;
  digest?: string; // GH returns "sha256:..." for newer releases; falls back to fetch+compute
};

type GithubRelease = {
  tag_name: string;
  draft: boolean;
  prerelease: boolean;
  published_at: string;
  body: string | null;
  assets: GithubAsset[];
};

export type ParsedRelease = {
  version: string;
  channel: 'stable' | 'beta';
  publishedAt: string;
  notes: string | null;
  assets: ReleaseAssets;
};

/// Parses one GitHub release into our internal shape. Returns null if it
/// has no usable binary+sig pairs (e.g. an early tag without artifacts).
export function parseGithubRelease(
  r: GithubRelease,
  // Resolver for SHA-256 of an asset. The poller passes a function that
  // checks `asset.digest` first and falls back to an HTTP HEAD+stream as
  // needed. Tests pass a static map.
  resolveSha256: (name: string, url: string) => Promise<string | null>,
): Promise<ParsedRelease | null> {
  return parseGithubReleaseInternal(r, resolveSha256);
}

async function parseGithubReleaseInternal(
  r: GithubRelease,
  resolveSha256: (name: string, url: string) => Promise<string | null>,
): Promise<ParsedRelease | null> {
  if (r.draft) return null;
  // Tag may be "v0.6.0" or "0.6.0".
  const version = r.tag_name.startsWith('v') ? r.tag_name.slice(1) : r.tag_name;
  if (!/^\d+\.\d+\.\d+$/.test(version)) return null;

  const channel: 'stable' | 'beta' = r.prerelease ? 'beta' : 'stable';

  // Group assets by triple. Each triple needs both a raw binary and a .sig.
  const sigs = new Map<string, GithubAsset>();
  const bins = new Map<string, GithubAsset>();
  for (const a of r.assets) {
    if (a.name.endsWith('.sig')) {
      const base = a.name.slice(0, -4);
      const m = base.match(ASSET_RE);
      if (m?.groups && m.groups.version === version) {
        const triple = m.groups.triple + (m.groups.ext ?? '');
        sigs.set(triple, a);
      }
      continue;
    }
    const m = a.name.match(ASSET_RE);
    if (m?.groups && m.groups.version === version) {
      const triple = m.groups.triple + (m.groups.ext ?? '');
      bins.set(triple, a);
    }
  }

  const assets: ReleaseAssets = {};
  for (const [triple, bin] of bins) {
    const sig = sigs.get(triple);
    if (!sig) continue;
    const sha = await resolveSha256(bin.name, bin.browser_download_url);
    if (!sha) continue;
    assets[stripExe(triple)] = {
      url: bin.browser_download_url,
      sig_url: sig.browser_download_url,
      sha256: sha,
    };
  }

  if (Object.keys(assets).length === 0) return null;
  return {
    version,
    channel,
    publishedAt: r.published_at,
    notes: r.body,
    assets,
  };
}

// Windows: drop the trailing `.exe` from the asset-derived triple key so
// callers can look up `"x86_64-pc-windows-msvc"` uniformly. The download
// URL itself still ends in `.exe`.
function stripExe(triple: string): string {
  return triple.endsWith('.exe') ? triple.slice(0, -4) : triple;
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

/// Production resolver: trust GitHub's `digest` field when present
/// ("sha256:abc..."), otherwise download once and compute.
export async function defaultShaResolver(_name: string, url: string, digest?: string): Promise<string | null> {
  if (digest && digest.startsWith('sha256:')) {
    return digest.slice('sha256:'.length).toLowerCase();
  }
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'open-attest-server' },
    });
    if (!resp.ok) return null;
    const buf = await resp.arrayBuffer();
    const hashBuf = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(hashBuf)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Top-level poll
// ---------------------------------------------------------------------------

/// Polls GitHub once. On success, upserts releases and removes any locally
/// cached versions that have disappeared from GH. On failure, leaves the
/// cache untouched.
export async function pollReleases(db: DB): Promise<{
  fetched: number;
  upserted: string[];
  dropped: string[];
  error?: string;
}> {
  let resp: Response;
  try {
    resp = await fetch(RELEASES_URL, {
      headers: {
        'User-Agent': 'open-attest-server',
        Accept: 'application/vnd.github+json',
      },
    });
  } catch (e) {
    return { fetched: 0, upserted: [], dropped: [], error: `fetch failed: ${e}` };
  }
  if (!resp.ok) {
    return {
      fetched: 0,
      upserted: [],
      dropped: [],
      error: `github returned ${resp.status}`,
    };
  }

  const releases = (await resp.json()) as GithubRelease[];
  const upserted: string[] = [];
  const seen = new Set<string>();

  for (const r of releases) {
    const parsed = await parseGithubReleaseInternal(r, (name, url) => {
      const asset = r.assets.find((a) => a.name === name);
      return defaultShaResolver(name, url, asset?.digest);
    });
    if (!parsed) continue;
    seen.add(parsed.version);

    // Keep admin-set rollout_percent when re-upserting an existing row.
    const existing = await getRelease(db, parsed.version);
    await upsertRelease(db, {
      version: parsed.version,
      channel: parsed.channel,
      publishedAt: parsed.publishedAt,
      notes: parsed.notes,
      assetsJson: JSON.stringify(parsed.assets),
      rolloutPercent: existing?.rolloutPercent ?? 100,
    });
    upserted.push(parsed.version);
  }

  // Drop locally-cached versions that GH no longer returns. Tags can be
  // deleted upstream — we don't want to keep offering a release that no
  // longer exists.
  const cached = await listReleases(db);
  const dropped: string[] = [];
  for (const row of cached) {
    if (!seen.has(row.version)) {
      await deleteRelease(db, row.version);
      dropped.push(row.version);
    }
  }

  return { fetched: releases.length, upserted, dropped };
}
