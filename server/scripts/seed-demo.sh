#!/bin/bash
set -euo pipefail

# Seed 50 demo devices for open-attest.
# Usage: ./scripts/seed-demo.sh [--server URL] [--secret ADMIN_SECRET]

SERVER="http://localhost:8787"
SECRET="dev-secret-change-me"

while [[ $# -gt 0 ]]; do
  case $1 in
    --server) SERVER="$2"; shift 2 ;;
    --secret) SECRET="$2"; shift 2 ;;
    *) shift ;;
  esac
done

echo "Seeding 50 demo devices on $SERVER"
echo ""

api() {
  curl -s -X "$1" "${SERVER}${2}" \
    -H "Authorization: Bearer $SECRET" \
    -H "Content-Type: application/json" \
    ${3:+-d "$3"}
}

# --- API keys ---
echo "Creating API keys..."
for label in "production" "staging" "ci-read-only" "screenata-integration"; do
  RESULT=$(api POST /v1/admin/api-keys "{\"org_id\":\"acme-corp\",\"label\":\"$label\"}")
  KEY=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key','error'))" 2>/dev/null)
  echo "  $label: $KEY"
done
echo ""

# --- Enrollment tokens ---
echo "Creating enrollment tokens..."
for i in $(seq 1 10); do
  TTL=$(( (i % 4 + 1) * 24 ))
  api POST /v1/admin/tokens "{\"org_id\":\"acme-corp\",\"expires_in_hours\":$TTL}" > /dev/null
done
# Mark some as used/expired by inserting directly
echo "  Created 10 tokens"
echo ""

# --- Devices ---
WRANGLER="npx wrangler d1 execute open-attest --local"

FIRSTNAMES=(
  "tao" "jane" "mike" "sarah" "alex" "emma" "liam" "olivia" "noah" "ava"
  "james" "sophia" "ben" "mia" "lucas" "isabella" "henry" "amelia" "jack" "harper"
  "logan" "evelyn" "daniel" "aria" "matt" "ella" "owen" "chloe" "ryan" "luna"
  "sam" "grace" "leo" "zoe" "ethan" "lily" "nathan" "layla" "caleb" "riley"
  "dylan" "nora" "andrew" "ellie" "max" "stella" "tyler" "maya" "kevin" "violet"
)

SUFFIXES=(
  "mbp" "air" "imac" "pro" "mini" "thinkpad" "xps" "surface" "latitude" "desktop"
)

MACOS_VERSIONS=("14.6.1" "14.5" "15.0" "15.1" "13.6.1" "14.4" "15.0.1" "14.3")
WIN_VERSIONS=("10.0.22631" "10.0.19045" "10.0.22621" "10.0.26100")

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

rand_minutes_ago() {
  local mins=$1
  # macOS date
  date -u -v-"${mins}M" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
  date -u -d "$mins minutes ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
  echo "$NOW"
}

echo "Seeding 50 devices..."

for i in $(seq 0 49); do
  name="${FIRSTNAMES[$i]}"
  suffix_idx=$(( i % ${#SUFFIXES[@]} ))
  suffix="${SUFFIXES[$suffix_idx]}"
  hostname="${name}-${suffix}"
  device_id="dev_$(printf '%03d' $((i + 1)))"
  agent_id="agent_$(printf '%03d' $((i + 1)))"
  key_id="key_demo_$(printf '%03d' $((i + 1)))"

  # Platform: 70% macOS, 30% Windows
  if (( i % 10 < 7 )); then
    platform="macos"
    ver_idx=$(( i % ${#MACOS_VERSIONS[@]} ))
    version="${MACOS_VERSIONS[$ver_idx]}"
  else
    platform="windows"
    ver_idx=$(( i % ${#WIN_VERSIONS[@]} ))
    version="${WIN_VERSIONS[$ver_idx]}"
  fi

  # Status: 90% active, 10% revoked
  if (( i % 10 == 9 )); then
    status="revoked"
  else
    status="active"
  fi

  # Last seen: varies
  # 60% — 1-10 min ago (healthy)
  # 20% — 1-4 hours ago (stale)
  # 10% — 1-7 days ago (very stale)
  # 10% — revoked (2+ days ago)
  if (( i % 10 < 6 )); then
    mins=$(( (i % 10) + 1 ))
    last_seen=$(rand_minutes_ago $mins)
  elif (( i % 10 < 8 )); then
    mins=$(( 60 + (i % 4) * 60 ))
    last_seen=$(rand_minutes_ago $mins)
  elif (( i % 10 == 8 )); then
    mins=$(( 1440 + (i % 7) * 1440 ))
    last_seen=$(rand_minutes_ago $mins)
  else
    mins=$(( 2880 + (i % 5) * 1440 ))
    last_seen=$(rand_minutes_ago $mins)
  fi

  # Compliance profile
  # 70% fully compliant
  # 15% partially compliant (some checks fail)
  # 15% non-compliant (most checks fail)
  if (( i % 20 < 14 )); then
    profile="compliant"
  elif (( i % 20 < 17 )); then
    profile="partial"
  else
    profile="noncompliant"
  fi

  echo "  [$((i+1))/50] $hostname ($platform $version) — $status, $profile"

  # Insert agent
  $WRANGLER --command "INSERT OR IGNORE INTO agents (agent_id, org_id, public_key, key_id, hostname, platform, platform_version, device_id, status, last_seen_at) VALUES ('$agent_id', 'acme-corp', 'demo-key-base64-placeholder', '$key_id', '$hostname', '$platform', '$version', '$device_id', '$status', '$last_seen');" 2>/dev/null

  # Build checks based on profile
  case "$profile" in
    compliant)
      disk="true"; fw="true"; sl_min="5"; sl_pw="true"; pw="true"; pw_min="8"
      edr="true"; mdm="true"; admin="false"
      ;;
    partial)
      # Some things off
      case $(( i % 3 )) in
        0) disk="true"; fw="false"; sl_min="15"; sl_pw="true"; pw="true"; pw_min="8"; edr="true"; mdm="false"; admin="true" ;;
        1) disk="true"; fw="true"; sl_min="30"; sl_pw="false"; pw="true"; pw_min="0"; edr="false"; mdm="true"; admin="false" ;;
        2) disk="false"; fw="true"; sl_min="5"; sl_pw="true"; pw="true"; pw_min="8"; edr="true"; mdm="true"; admin="true" ;;
      esac
      ;;
    noncompliant)
      disk="false"; fw="false"; sl_min="-1"; sl_pw="false"; pw="true"; pw_min="0"
      edr="false"; mdm="false"; admin="true"
      ;;
  esac

  # Insert checks
  CHECKS=(
    "disk_encryption.enabled|{\"type\":\"bool\",\"value\":$disk}|native_api"
    "firewall.enabled|{\"type\":\"bool\",\"value\":$fw}|native_api"
    "screen_lock.timeout_minutes|{\"type\":\"int\",\"value\":$sl_min}|native_api"
    "screen_lock.password_required|{\"type\":\"bool\",\"value\":$sl_pw}|sysadminctl"
    "password.enabled|{\"type\":\"bool\",\"value\":$pw}|dscl_authonly"
    "password_policy.min_length|{\"type\":\"int\",\"value\":$pw_min}|pwpolicy"
    "os.version|{\"type\":\"string\",\"value\":\"$version\"}|sw_vers"
    "edr.present|{\"type\":\"bool\",\"value\":$edr}|process_scan"
    "mdm.enrolled|{\"type\":\"bool\",\"value\":$mdm}|profiles_cmd"
    "local_admin.is_admin|{\"type\":\"bool\",\"value\":$admin}|dscl"
    "hostname|{\"type\":\"string\",\"value\":\"$hostname\"}|syscall"
    "user.primary|{\"type\":\"string\",\"value\":\"$name\"}|whoami"
    "local_admin.members|{\"type\":\"string_list\",\"value\":[\"root\",\"$name\"]}|dscl"
  )

  for check_str in "${CHECKS[@]}"; do
    IFS='|' read -r key value source <<< "$check_str"
    $WRANGLER --command "INSERT OR REPLACE INTO device_checks (device_id, check_key, check_value, observed_at, source) VALUES ('$device_id', '$key', '$value', '$last_seen', '$source');" 2>/dev/null
  done
done

# Also insert some used/expired tokens directly for variety
$WRANGLER --command "INSERT OR IGNORE INTO enrollment_tokens (id, token, org_id, used, revoked, expires_at) VALUES ('tok_used_1', 'oat_used_demo_1', 'acme-corp', 1, 0, '$NOW'), ('tok_used_2', 'oat_used_demo_2', 'acme-corp', 1, 0, '$NOW'), ('tok_used_3', 'oat_used_demo_3', 'acme-corp', 1, 0, '$NOW'), ('tok_revoked_1', 'oat_revoked_demo_1', 'acme-corp', 0, 1, '$NOW'), ('tok_expired_1', 'oat_expired_demo_1', 'acme-corp', 0, 0, '2025-01-01T00:00:00Z');" 2>/dev/null

echo ""
echo "Done! Seeded:"
echo "  50 devices (35 compliant, 8 partial, 7 non-compliant, 5 revoked)"
echo "  4 API keys"
echo "  15 enrollment tokens (10 available, 3 used, 1 revoked, 1 expired)"
echo ""
echo "Open: ${SERVER}/admin/"
