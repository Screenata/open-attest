#!/bin/bash
set -euo pipefail

# Usage: ./build-pkg.sh --token <enrollment_token> --server <server_url> [--output <output.pkg>]

TOKEN=""
SERVER_URL=""
OUTPUT="open-attest.pkg"
IDENTIFIER="com.open-attest.agent"
VERSION="0.2.0"

while [[ $# -gt 0 ]]; do
    case $1 in
        --token) TOKEN="$2"; shift 2 ;;
        --server) SERVER_URL="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$TOKEN" ] || [ -z "$SERVER_URL" ]; then
    echo "Usage: ./build-pkg.sh --token <token> --server <server_url>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR=$(mktemp -d)
PAYLOAD_DIR="$BUILD_DIR/payload"
SCRIPTS_DIR="$BUILD_DIR/scripts"

# Build the agent binary (release mode)
echo "Building open-attest agent..."
cd "$AGENT_DIR"
cargo build --release

# Create payload (files to install)
mkdir -p "$PAYLOAD_DIR/usr/local/bin"
cp "$AGENT_DIR/target/release/open-attest" "$PAYLOAD_DIR/usr/local/bin/open-attest"
chmod 755 "$PAYLOAD_DIR/usr/local/bin/open-attest"

# Create postinstall script with embedded token
mkdir -p "$SCRIPTS_DIR"
cat > "$SCRIPTS_DIR/postinstall" << POSTINSTALL
#!/bin/bash
set -e

ENROLL_TOKEN="$TOKEN"
ENROLL_SERVER="$SERVER_URL"
INSTALL_USER=\$(stat -f "%Su" /dev/console)

# Run enrollment as the logged-in user
su "\$INSTALL_USER" -c "/usr/local/bin/open-attest enroll --token \"\$ENROLL_TOKEN\" --server \"\$ENROLL_SERVER\"" || {
    echo "Enrollment failed. The agent is installed but not enrolled."
    echo "Run: open-attest enroll --token <token> --server <server_url>"
    exit 0  # Don't fail the install if enrollment fails
}

echo "open-attest installed and enrolled successfully."
POSTINSTALL
chmod 755 "$SCRIPTS_DIR/postinstall"

# Create preinstall script to uninstall previous version
cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL'
#!/bin/bash
# If open-attest is already installed and enrolled, uninstall the daemon first
if [ -f /usr/local/bin/open-attest ]; then
    INSTALL_USER=$(stat -f "%Su" /dev/console)
    su "$INSTALL_USER" -c "/usr/local/bin/open-attest uninstall" 2>/dev/null || true
fi
PREINSTALL
chmod 755 "$SCRIPTS_DIR/preinstall"

# Build the .pkg
echo "Building .pkg installer..."
pkgbuild \
    --root "$PAYLOAD_DIR" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --install-location "/" \
    "$OUTPUT"

# Clean up
rm -rf "$BUILD_DIR"

echo ""
echo "Package built: $OUTPUT"
echo "  Token:  ${TOKEN:0:10}..."
echo "  Server: $SERVER_URL"
echo ""
echo "Distribute this .pkg to users. Double-click to install."
