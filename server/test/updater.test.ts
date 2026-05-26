import { describe, it, expect } from 'vitest';
import {
  parseVersion,
  compareVersions,
  semverDesc,
  stableHashPercent,
  pickOffer,
  type ReleaseSummary,
} from '../src/updater';
import type { AgentForOffer } from '../src/updater';

function agent(overrides: Partial<AgentForOffer> = {}): AgentForOffer {
  return {
    agentId: 'agent-1',
    deviceId: 'device-1',
    currentVersion: '0.5.0',
    targetTriple: 'aarch64-apple-darwin',
    targetVersion: null,
    updateChannel: 'stable',
    ...overrides,
  };
}

function release(overrides: Partial<ReleaseSummary> = {}): ReleaseSummary {
  return {
    version: '0.6.0',
    channel: 'stable',
    publishedAt: '2026-05-01T00:00:00Z',
    rolloutPercent: 100,
    assets: {
      'aarch64-apple-darwin': {
        url: 'https://example.com/bin',
        sig_url: 'https://example.com/bin.sig',
        sha256: 'abcd',
      },
      'x86_64-unknown-linux-gnu': {
        url: 'https://example.com/linux',
        sig_url: 'https://example.com/linux.sig',
        sha256: 'efgh',
      },
    },
    ...overrides,
  };
}

describe('parseVersion', () => {
  it('parses bare semver', () => {
    expect(parseVersion('0.6.0')).toEqual([0, 6, 0]);
    expect(parseVersion('1.2.3')).toEqual([1, 2, 3]);
    expect(parseVersion('10.20.30')).toEqual([10, 20, 30]);
  });
  it('strips leading v', () => {
    expect(parseVersion('v1.2.3')).toEqual([1, 2, 3]);
  });
  it('strips prerelease/build metadata', () => {
    expect(parseVersion('1.2.3-rc1')).toEqual([1, 2, 3]);
    expect(parseVersion('1.2.3+build5')).toEqual([1, 2, 3]);
  });
  it('rejects garbage', () => {
    expect(parseVersion('not a version')).toBeNull();
    expect(parseVersion('1.2')).toBeNull();
    expect(parseVersion('1.2.3.4')).toBeNull();
  });
});

describe('compareVersions', () => {
  it('orders correctly', () => {
    expect(compareVersions('0.5.0', '0.6.0')).toBeLessThan(0);
    expect(compareVersions('0.6.0', '0.5.0')).toBeGreaterThan(0);
    expect(compareVersions('0.6.0', '0.6.0')).toBe(0);
    expect(compareVersions('1.0.0', '0.99.0')).toBeGreaterThan(0);
  });
});

describe('semverDesc', () => {
  it('sorts newest first', () => {
    const versions = ['0.5.0', '0.7.1', '0.6.0', '1.0.0'];
    versions.sort(semverDesc);
    expect(versions).toEqual(['1.0.0', '0.7.1', '0.6.0', '0.5.0']);
  });
});

describe('stableHashPercent', () => {
  it('is deterministic', () => {
    expect(stableHashPercent('device-1', '0.6.0')).toBe(
      stableHashPercent('device-1', '0.6.0'),
    );
  });
  it('returns 0..99', () => {
    for (let i = 0; i < 100; i++) {
      const b = stableHashPercent(`device-${i}`, '0.6.0');
      expect(b).toBeGreaterThanOrEqual(0);
      expect(b).toBeLessThan(100);
    }
  });
  it('different versions of same device land in different buckets (usually)', () => {
    const a = stableHashPercent('device-1', '0.6.0');
    const b = stableHashPercent('device-1', '0.7.0');
    // Not strictly required, but a sanity check that we're not constant.
    expect(a).not.toBe(b);
  });
  it('rolling out 100% includes everyone', () => {
    for (let i = 0; i < 200; i++) {
      const b = stableHashPercent(`device-${i}`, 'X');
      expect(b).toBeLessThan(100);
    }
  });
  it('roughly uniform distribution', () => {
    const buckets = [0, 0, 0, 0]; // count [0..25), [25..50), [50..75), [75..100)
    for (let i = 0; i < 4000; i++) {
      const b = stableHashPercent(`device-${i}`, '0.6.0');
      buckets[Math.floor(b / 25)]++;
    }
    // Each quartile should be roughly 1000 (within 30%).
    for (const c of buckets) {
      expect(c).toBeGreaterThan(700);
      expect(c).toBeLessThan(1300);
    }
  });
});

describe('pickOffer', () => {
  it('returns null when no releases', () => {
    expect(pickOffer(agent(), [])).toBeNull();
  });

  it('returns null when already at latest', () => {
    expect(pickOffer(agent({ currentVersion: '0.6.0' }), [release()])).toBeNull();
  });

  it('offers the newest stable release in channel', () => {
    const offer = pickOffer(agent(), [release({ version: '0.6.0' }), release({ version: '0.7.0' })]);
    expect(offer?.version).toBe('0.7.0');
    expect(offer?.target_triple).toBe('aarch64-apple-darwin');
  });

  it('skips when device target_triple has no asset', () => {
    const r = release({ assets: { 'x86_64-unknown-linux-gnu': release().assets['x86_64-unknown-linux-gnu'] } });
    expect(pickOffer(agent(), [r])).toBeNull();
  });

  it('respects rollout_percent (excludes high-bucket devices)', () => {
    const lowRollout = release({ rolloutPercent: 1 });
    let offered = 0;
    let skipped = 0;
    for (let i = 0; i < 100; i++) {
      const a = agent({ deviceId: `device-${i}` });
      if (pickOffer(a, [lowRollout])) offered++;
      else skipped++;
    }
    // At ~1% rollout, ~1 of 100 should be offered.
    expect(offered).toBeGreaterThanOrEqual(0);
    expect(offered).toBeLessThanOrEqual(5);
    expect(skipped).toBeGreaterThanOrEqual(95);
  });

  it('rollout monotonicity: 10% bucket is a subset of 50% bucket', () => {
    const r10 = release({ rolloutPercent: 10 });
    const r50 = release({ rolloutPercent: 50 });
    for (let i = 0; i < 300; i++) {
      const a = agent({ deviceId: `device-${i}` });
      const in10 = pickOffer(a, [r10]) !== null;
      const in50 = pickOffer(a, [r50]) !== null;
      if (in10) expect(in50).toBe(true);
    }
  });

  it('paused channel disables all offers', () => {
    expect(pickOffer(agent({ updateChannel: 'paused' }), [release()])).toBeNull();
  });

  it('beta channel sees only prerelease versions', () => {
    const stable = release({ version: '0.6.0', channel: 'stable' });
    const beta = release({ version: '0.7.0-rc1', channel: 'beta' });
    // Note: parseVersion strips -rc1, so 0.7.0 beta > 0.6.0 stable for beta channel.
    expect(pickOffer(agent({ updateChannel: 'beta' }), [stable, beta])?.version).toBe('0.7.0-rc1');
    expect(pickOffer(agent({ updateChannel: 'stable' }), [stable, beta])?.version).toBe('0.6.0');
  });

  it('pin overrides channel and bypasses rollout', () => {
    const r05 = release({ version: '0.5.0', rolloutPercent: 0 });
    const r06 = release({ version: '0.6.0', rolloutPercent: 0 });
    const offer = pickOffer(
      agent({ currentVersion: '0.4.0', targetVersion: '0.5.0', updateChannel: 'beta' }),
      [r05, r06],
    );
    expect(offer?.version).toBe('0.5.0');
    expect(offer?.force).toBe(true);
  });

  it('paused channel beats pin (paused is the kill switch)', () => {
    const r05 = release({ version: '0.5.0' });
    expect(
      pickOffer(
        agent({ currentVersion: '0.4.0', targetVersion: '0.5.0', updateChannel: 'paused' }),
        [r05],
      ),
    ).toBeNull();
  });

  it('pin returns null if pinned version is missing', () => {
    expect(
      pickOffer(agent({ targetVersion: '99.0.0' }), [release()]),
    ).toBeNull();
  });

  it('pin returns null if already at pinned version', () => {
    expect(
      pickOffer(agent({ currentVersion: '0.6.0', targetVersion: '0.6.0' }), [release()]),
    ).toBeNull();
  });

  it('never downgrades without pin', () => {
    const older = release({ version: '0.4.0' });
    expect(pickOffer(agent({ currentVersion: '0.6.0' }), [older])).toBeNull();
  });

  it('skips when agent has no target_triple yet (pre-0.6 client)', () => {
    expect(pickOffer(agent({ targetTriple: null }), [release()])).toBeNull();
  });
});
