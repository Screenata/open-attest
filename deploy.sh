#!/bin/bash
set -euo pipefail

# Deploy script for Cloudflare's "Deploy with Workers" button.
# This runs automatically when someone clicks the deploy button.

cd server
npm install

# Create D1 database
DB_OUTPUT=$(npx wrangler d1 create open-attest 2>&1) || true
DB_ID=$(echo "$DB_OUTPUT" | grep -oP 'database_id = "\K[^"]+' || echo "")

if [ -n "$DB_ID" ]; then
  # Update wrangler.toml with the real database ID
  sed -i.bak "s/database_id = \"local\"/database_id = \"$DB_ID\"/" wrangler.toml
  rm -f wrangler.toml.bak
fi

# Run migrations
npx wrangler d1 execute open-attest --remote --file=schema.sql || true

# Generate a random admin secret
ADMIN_SECRET=$(openssl rand -hex 32)
echo "$ADMIN_SECRET" | npx wrangler secret put ADMIN_SECRET || true

# Remove dev-only ADMIN_SECRET from vars (production uses the secret)
sed -i.bak '/^\[vars\]/,/^$/d' wrangler.toml
rm -f wrangler.toml.bak

# Deploy
npx wrangler deploy

echo ""
echo "========================================="
echo "  open-attest server deployed!"
echo "========================================="
echo ""
echo "Your admin secret: $ADMIN_SECRET"
echo ""
echo "Save this secret. Use it to create API keys and enrollment tokens."
echo ""
echo "Next steps:"
echo "  1. Create an API key:"
echo "     curl -X POST https://open-attest-server.<your-subdomain>.workers.dev/v1/admin/api-keys \\"
echo "       -H 'Authorization: Bearer $ADMIN_SECRET' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"org_id\": \"my-company\"}'"
echo ""
echo "  2. Create an enrollment token:"
echo "     curl -X POST https://open-attest-server.<your-subdomain>.workers.dev/v1/admin/tokens \\"
echo "       -H 'Authorization: Bearer $ADMIN_SECRET' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"org_id\": \"my-company\"}'"
echo ""
echo "  3. Install the agent on a device:"
echo "     open-attest enroll --token <TOKEN> --server https://open-attest-server.<your-subdomain>.workers.dev"
echo ""
