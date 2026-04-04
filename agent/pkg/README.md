# Building the open-attest .pkg installer

The .pkg installer bundles the open-attest agent binary with an enrollment token,
so end users can install with a double-click — no terminal required.

## Prerequisites

- macOS with Xcode command line tools (`xcode-select --install`)
- Rust toolchain (`rustup`)
- An enrollment token from your open-attest server

## Build

```bash
./build-pkg.sh --token <enrollment_token> --server https://your-server.workers.dev
```

This will:
1. Build the agent in release mode
2. Create a .pkg that installs to /usr/local/bin/open-attest
3. Embed a postinstall script that runs enrollment automatically

## Output

The resulting .pkg file can be distributed to users. When they double-click it:
1. macOS installer wizard runs (requires admin password)
2. Binary is installed to /usr/local/bin/
3. Postinstall script runs enrollment with the embedded token
4. LaunchAgent is installed and daemon starts

## Signing (recommended for distribution)

For production distribution, sign the package:
```bash
productsign --sign "Developer ID Installer: Your Name (TEAM_ID)" open-attest.pkg open-attest-signed.pkg
```

And notarize:
```bash
xcrun notarytool submit open-attest-signed.pkg --apple-id <email> --team-id <TEAM_ID> --password <app-specific-password> --wait
xcrun stapler staple open-attest-signed.pkg
```
