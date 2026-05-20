# sign-release

Build-time tool for signing open-attest release binaries with the Ed25519
release key. Not installed on devices.

> **🚨 ROTATE THE DEV KEY BEFORE FIRST PRODUCTION RELEASE 🚨**
>
> The currently-committed `agent/release_pubkey.bin` was generated during
> initial setup and the corresponding private seed was printed in a chat
> transcript. **It is compromised by design** and must be rotated before
> tagging any release that real devices will trust.
>
> To rotate: run the keygen command in [One-time setup](#one-time-setup),
> commit the new `agent/release_pubkey.bin`, and update the
> `RELEASE_PRIVKEY` GitHub Actions secret to the new seed.

## One-time setup

Generate the release keypair (run **once**, on a machine you trust):

```bash
cargo run -p sign-release -- keygen --out-pub agent/release_pubkey.bin
```

This:

- Writes the 32-byte raw public key to `agent/release_pubkey.bin` (commit
  this to the repo — the agent embeds it via `include_bytes!`).
- Prints the 32-byte private seed (hex) to stdout.

Take the printed private seed and add it to GitHub Actions secrets:

- Settings → Secrets and variables → Actions → New repository secret
- Name: `RELEASE_PRIVKEY`
- Value: the hex string printed by keygen

Then erase the seed from your shell history. The repo never needs to see
the private seed again.

## Per-release

Invoked from `.github/workflows/release.yml` for each target binary:

```bash
cargo run -p sign-release -- sign \
  --key "$RELEASE_PRIVKEY" \
  --input path/to/open-attest \
  --out  path/to/open-attest.sig
```

The `.sig` output is a hex-encoded 64-byte Ed25519 signature over the raw
binary bytes (no envelope).

## Sanity-check locally

```bash
cargo run -p sign-release -- verify \
  --pubkey agent/release_pubkey.bin \
  --input  path/to/open-attest \
  --sig    path/to/open-attest.sig
```

## Key rotation (future)

Out of scope for v1. When we rotate, we embed both old and new public keys
in the agent for one release cycle, then drop the old key.
