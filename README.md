# open-attest

Lightweight, open-source endpoint attestation for SOC 2. Collects signed endpoint posture facts and exposes them through an open API — no MDM, no infrastructure, no complexity.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/screenata/open-attest)

## Why

Startups preparing for SOC 2 need endpoint evidence but don't need (or want) a full MDM. The usual options are manual screenshots, heavyweight device management platforms, or tools that cost more than your seed round.

open-attest is built for teams of 5-50 where the CTO is also the IT admin. Deploy the server in one click, install the agent in two commands, and you have signed endpoint compliance evidence flowing in under 10 minutes.

- **Free to run** — Cloudflare Workers free tier handles ~50 devices
- **Zero infrastructure** — no servers, no databases to manage, no Docker
- **Two commands to install** — `brew install` + `open-attest enroll`
- **Runs silently** — daemon starts on boot, reports hourly, no user interaction
- **Signed attestations** — Ed25519 signatures, tamper-evident, auditor-friendly
- **Open source** — inspect every check, every byte sent to the server

## What it does

open-attest runs on your team's laptops and reports security posture to a central server. It collects facts like:

- Disk encryption (FileVault / BitLocker)
- Firewall status
- Screen lock timeout and password requirement
- OS version
- EDR/antivirus presence
- Password policy
- Local admin membership
- MDM enrollment

Every attestation is signed with Ed25519 so the server can verify it came from a registered agent and hasn't been tampered with.

## Architecture

```
Agent (Rust)  -->  Reference Server (Cloudflare Workers + D1)  -->  Screenata / your GRC
```

- **Agent**: Rust binary, runs as a background daemon, collects posture checks, signs and submits attestations
- **Server**: TypeScript on Cloudflare Workers with D1 (SQLite). Zero infrastructure to manage. Free tier covers ~50 devices
- **Screenata** (optional): Adds control mapping, policy evaluation, evidence generation, and auditor exports

## Quick start

### Deploy the server

```bash
cd server
npm install
wrangler d1 create open-attest          # create D1 database
# Update wrangler.toml with the database_id from above
wrangler secret put ADMIN_SECRET        # set your admin secret
npm run db:migrate:production           # apply migrations
wrangler deploy                         # deploy to Cloudflare
```

### Create credentials

```bash
# Create an admin API key
curl -X POST https://your-worker.workers.dev/v1/admin/api-keys \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "my-company"}'

# Create an enrollment token
curl -X POST https://your-worker.workers.dev/v1/admin/tokens \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "my-company"}'
```

### Install the agent

Download from [GitHub Releases](../../releases) or build from source:

```bash
cd agent
cargo build --release
```

Enroll and start:

```bash
open-attest enroll --token <TOKEN> --server https://your-worker.workers.dev
```

The agent enrolls, installs a LaunchAgent, and starts reporting automatically. No further action needed.

### View devices

```bash
curl https://your-worker.workers.dev/v1/devices \
  -H "Authorization: Bearer <API_KEY>"
```

## Agent checks

| Check | Key | Type | macOS | Windows |
|-------|-----|------|-------|---------|
| Disk encryption | `disk_encryption.enabled` | bool | FileVault | BitLocker |
| Firewall | `firewall.enabled` | bool | Application Firewall | Windows Firewall |
| Screen lock timeout | `screen_lock.timeout_minutes` | int | Screensaver idle time | Registry / powercfg |
| Screen lock password | `screen_lock.password_required` | bool | sysadminctl | Registry |
| Login password set | `password.enabled` | bool | dscl authonly | net user |
| Password policy | `password_policy.min_length` | int | pwpolicy | ADSI / net accounts |
| OS version | `os.version` | string | sw_vers | .NET Environment |
| Hostname | `hostname` | string | hostname | hostname |
| Primary user | `user.primary` | string | whoami | whoami |
| MDM enrollment | `mdm.enrolled` | bool | profiles | dsregcmd |
| EDR/AV presence | `edr.present` | bool | XProtect + process scan | SecurityCenter2 + Defender |
| Local admin | `local_admin.is_admin` | bool | dscl | net localgroup |
| Admin members | `local_admin.members` | string[] | dscl | net localgroup |

## API

All endpoints require authentication. Agent endpoints use Ed25519 signatures. Admin endpoints use API keys.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | None | Health check |
| POST | `/v1/admin/api-keys` | Admin secret | Create API key |
| POST | `/v1/admin/tokens` | Admin secret | Create enrollment token |
| GET | `/v1/admin/status` | Admin secret | Server stats |
| POST | `/v1/agents/enroll` | Token | Enroll agent |
| POST | `/v1/agents/revoke` | API key | Revoke agent |
| POST | `/v1/agents/rekey` | Agent sig | Rotate key |
| POST | `/v1/attestations` | Agent sig | Submit attestation |
| POST | `/v1/heartbeat` | Agent sig | Heartbeat |
| GET | `/v1/devices` | API key | List devices |
| GET | `/v1/devices/:id` | API key | Device + checks |
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
npm run db:migrate:local    # apply migrations to local D1
npm run dev                 # start local server on :8787
npm test                    # run tests (31 tests)
```

To add a new migration after changing `src/schema.ts`:

```bash
npm run db:generate         # generate migration from schema changes
```

### Agent

```bash
cd agent
cargo build
cargo test                  # run tests (81 tests)
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
