#!/bin/bash
set -euo pipefail

# Usage: ./build-pkg.sh --token <enrollment_token> --server <server_url> [--output <output.pkg>]

TOKEN=""
SERVER_URL=""
OUTPUT="open-attest.pkg"
IDENTIFIER="com.open-attest.agent"
VERSION="0.6.0"

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

# Stage the binary at a system-writable scratch location during install;
# the postinstall script moves it to the per-user managed path.
mkdir -p "$PAYLOAD_DIR/usr/local/bin"
cp "$AGENT_DIR/target/release/open-attest" "$PAYLOAD_DIR/usr/local/bin/open-attest.staged"
chmod 755 "$PAYLOAD_DIR/usr/local/bin/open-attest.staged"

mkdir -p "$SCRIPTS_DIR"

# Preinstall: clean up an existing user-level install before laying down a new one.
cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL'
#!/bin/bash
INSTALL_USER=$(stat -f "%Su" /dev/console)
USER_HOME=$(eval echo "~$INSTALL_USER")
USER_BIN="$USER_HOME/Library/Application Support/open-attest/bin/open-attest"
if [ -x "$USER_BIN" ]; then
    su "$INSTALL_USER" -c "\"$USER_BIN\" uninstall" 2>/dev/null || true
fi
PREINSTALL
chmod 755 "$SCRIPTS_DIR/preinstall"

# Postinstall: move staged binary into the logged-in user's managed path,
# fix ownership/permissions, then run enrollment as that user.
cat > "$SCRIPTS_DIR/postinstall" << POSTINSTALL
#!/bin/bash
set -e

ENROLL_TOKEN="$TOKEN"
ENROLL_SERVER="$SERVER_URL"
INSTALL_USER=\$(stat -f "%Su" /dev/console)
USER_HOME=\$(eval echo "~\$INSTALL_USER")
USER_BASE="\$USER_HOME/Library/Application Support/open-attest"
USER_BIN="\$USER_BASE/bin"

mkdir -p "\$USER_BIN"
mv /usr/local/bin/open-attest.staged "\$USER_BIN/open-attest"
chown -R "\$INSTALL_USER:staff" "\$USER_BASE"
chmod 755 "\$USER_BIN/open-attest"

# Run enrollment as the logged-in user. install_launchd inside the agent
# writes a LaunchAgent plist pointing at the user-managed binary path.
su "\$INSTALL_USER" -c "\"\$USER_BIN/open-attest\" enroll --token \"\$ENROLL_TOKEN\" --server \"\$ENROLL_SERVER\"" || {
    echo "Enrollment failed. The agent is installed but not enrolled."
    echo "Run: \"\$USER_BIN/open-attest\" enroll --token <token> --server <server_url>"
    exit 0  # Don't fail the install if enrollment fails
}

echo "open-attest installed at \$USER_BIN/open-attest and enrolled successfully."
POSTINSTALL
chmod 755 "$SCRIPTS_DIR/postinstall"

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
