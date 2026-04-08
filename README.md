# open-attest

Lightweight, open-source endpoint attestation for SOC 2. Collects signed endpoint posture facts and exposes them through an open API — no MDM, no infrastructure, no complexity.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/screenata/open-attest/tree/main/server)

## Why

Startups preparing for SOC 2 need endpoint evidence but don't need (or want) a full MDM. The usual options are manual screenshots, heavyweight device management platforms, or tools that cost more than your seed round.

open-attest is built for teams of 5-50 where the CTO is also the IT admin. Deploy the server in one click, install the agent in one command, and you have signed endpoint compliance evidence flowing in under 10 minutes.

- **Free to run** — Cloudflare Workers free tier handles ~50 devices
- **Zero infrastructure** — no servers, no databases to manage, no Docker
- **One command to install** — download binary, run `open-attest enroll`
- **Runs silently** — daemon starts on boot, reports hourly, no user interaction
- **Signed attestations** — Ed25519 signatures, tamper-evident, auditor-friendly
- **Cross-platform** — macOS, Windows, and Linux
- **Admin UI included** — dashboard, device list, compliance status, credential management
- **Open source** — inspect every check, every byte sent to the server

## What it does

open-attest runs on your team's laptops and reports security posture to a central server. It collects 13 posture checks:

- Disk encryption (FileVault / BitLocker / LUKS)
- Firewall status
- Screen lock timeout and password requirement
- OS version
- EDR/antivirus presence (XProtect, CrowdStrike, SentinelOne, AppArmor, SELinux, etc.)
- Password policy and login password
- Local admin membership
- MDM enrollment

Every attestation is signed with Ed25519 so the server can verify it came from a registered agent and hasn't been tampered with.

## Architecture

```
Agent (Rust)  -->  Reference Server (Cloudflare Workers + D1)  -->  Screenata / your GRC
                         |
                    Admin UI (React)
```

- **Agent**: Rust binary (macOS, Windows, Linux), runs as a background daemon, collects posture checks, signs and submits attestations
- **Server**: TypeScript on Cloudflare Workers with D1 (SQLite) and Drizzle ORM. Zero infrastructure to manage. Free tier covers ~50 devices
- **Admin UI**: React SPA with shadcn/ui — dashboard, device compliance, credential management. Served from the same Worker
- **Screenata** (optional): Adds control mapping, policy evaluation, evidence generation, and auditor exports

## Quick start

### Deploy the server

```bash
cd server
npm install
cd admin && npm install && cd ..    # install admin UI deps
wrangler d1 create open-attest      # create D1 database
# Update wrangler.toml with the database_id from above
wrangler secret put ADMIN_SECRET    # set your admin secret
npm run db:migrate:production       # apply migrations
npm run deploy:production           # build admin UI + deploy
```

Or click the "Deploy to Cloudflare Workers" button above for one-click deploy.

### Set up

1. Open `https://your-worker.workers.dev/admin/` and log in with your admin secret
2. Go to **Credentials** → **Create Enrollment Token** (set max devices, e.g. 50)
3. Copy the enrollment link and share it with your team

### Install the agent

Employees open the enrollment link and follow the instructions, or run directly:

```bash
open-attest enroll --token <TOKEN> --server https://your-worker.workers.dev
```

The agent enrolls, installs a background daemon, and starts reporting automatically.

### CLI commands

```bash
open-attest check           # show posture checks with pass/fail status
open-attest check --json    # machine-readable JSON output
open-attest status          # show agent enrollment status
open-attest attest          # submit an attestation now
open-attest web             # open admin UI in browser
open-attest uninstall       # remove agent and daemon
```

## Agent checks

| Check | Key | Type | macOS | Windows | Linux |
|-------|-----|------|-------|---------|-------|
| Disk encryption | `disk_encryption.enabled` | bool | FileVault | BitLocker | LUKS / dm-crypt |
| Firewall | `firewall.enabled` | bool | Application Firewall | Windows Firewall | ufw / iptables / firewalld |
| Screen lock timeout | `screen_lock.timeout_minutes` | int | Screensaver idle time | Registry / powercfg | gsettings / KDE / XFCE |
| Screen lock password | `screen_lock.password_required` | bool | sysadminctl | Registry | gsettings / KDE / XFCE |
| Login password set | `password.enabled` | bool | dscl authonly | net user | /etc/shadow |
| Password policy | `password_policy.min_length` | int | pwpolicy | ADSI / net accounts | PAM / pwquality / login.defs |
| OS version | `os.version` | string | sw_vers | .NET Environment | /etc/os-release |
| Hostname | `hostname` | string | hostname | hostname | hostname |
| Primary user | `user.primary` | string | whoami | whoami | whoami |
| MDM enrollment | `mdm.enrolled` | bool | profiles | dsregcmd | N/A |
| EDR/AV presence | `edr.present` | bool | XProtect + process scan | SecurityCenter2 + Defender | Process scan + AppArmor/SELinux |
| Local admin | `local_admin.is_admin` | bool | dscl | net localgroup | /etc/group (sudo/wheel) |

## Compliance evaluation

The CLI and admin UI evaluate checks against default thresholds:

| Check | Rule | Status |
|-------|------|--------|
| Disk encryption | must be enabled | Pass / Fail |
| Firewall | must be enabled | Pass / Fail |
| Screen lock password | must be required | Pass / Fail |
| Login password | must be set | Pass / Fail |
| Screen lock timeout | must be ≤ 15 minutes | Pass / Fail |
| Password min length | must be ≥ 8 characters | Pass / Fail |
| EDR/AV presence | should be present | Pass / Warning |
| Local admin | user should not be admin | Pass / Warning |
| MDM enrollment | informational | — |

## API

All endpoints require authentication. Agent endpoints use Ed25519 signatures. Admin endpoints use API keys or the admin secret.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| GET | `/admin/` | None | Admin UI |
| GET | `/enroll/:token` | None | Enrollment page for employees |
| POST | `/v1/admin/api-keys` | Admin secret | Create API key |
| GET | `/v1/admin/api-keys` | Admin secret | List API keys |
| DELETE | `/v1/admin/api-keys` | Admin secret | Delete API key |
| POST | `/v1/admin/tokens` | Admin secret | Create enrollment token (multi-use) |
| GET | `/v1/admin/tokens` | Admin secret | List enrollment tokens |
| GET | `/v1/admin/status` | Admin secret | Server stats + compliance summary |
| POST | `/v1/agents/enroll` | Token | Enroll agent |
| POST | `/v1/agents/revoke` | API key | Revoke agent |
| POST | `/v1/agents/rekey` | Agent sig | Rotate key |
| POST | `/v1/attestations` | Agent sig | Submit attestation |
| POST | `/v1/heartbeat` | Agent sig | Heartbeat |
| GET | `/v1/devices` | API key | List devices |
| GET | `/v1/devices/:id` | API key | Device + posture checks |
| GET | `/v1/attestations/:id` | API key | Attestation detail |

## Building a .pkg installer (macOS)

For distributing to non-technical users:

```bash
cd agent/pkg
./build-pkg.sh --token <TOKEN> --server https://your-worker.workers.dev
```

Produces a `.pkg` that installs the agent and enrolls automatically.

## Development

### Server

```bash
cd server
npm install
cd admin && npm install && cd ..
npm run db:migrate:local    # apply migrations to local D1
npm run dev                 # build admin UI + start local server on :8787
npm test                    # run tests (32 tests)
```

To add a new migration after changing `src/schema.ts`:

```bash
npm run db:generate         # generate migration from schema changes
```

### Agent

```bash
cd agent
cargo build
cargo test                  # run tests (119 tests)
```

### Demo data

```bash
cd server
./scripts/seed-demo.sh      # seed 50 demo devices with realistic data
```

## Trust model

Attestations are best-effort, self-reported posture statements from the endpoint. Signatures prove origin authenticity and record integrity, but do not prove the endpoint is uncompromised or that every reported fact is unforgeable under full host compromise.

## Screenata

open-attest gives you the raw posture data. [Screenata](https://screenata.com) turns it into audit-ready compliance evidence.

- Map endpoint checks to SOC 2 controls
- Set pass/fail thresholds per org
- Generate evidence summaries for auditors
- Track drift and exceptions over time
- Export PDF/CSV reports with one click

open-attest + Screenata = endpoint compliance without the MDM.

## License

[MIT](LICENSE)
