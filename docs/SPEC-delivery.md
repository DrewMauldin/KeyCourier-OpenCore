# Spec: KeyCourier delivery

## Objective

Install an approved secret into a preconfigured consumer without exposing it to the requesting AI client.

## V1 destinations

- Local dotenv file with a fixed absolute path and fixed variable name
- Remote destination metadata that reports `notConfigured` until a host agent is installed

The vault itself uses the macOS Keychain. Keychain mirroring for arbitrary third-party consumers is excluded because macOS access groups and caller identity need a signed deployment design.

## Required behaviour

- Consumer profiles are created by the owner, not by request payloads.
- Dotenv values are single-line only, escaped with deterministic double-quote rules.
- Existing files receive a mode-600 protected previous-version backup.
- Replacement is atomic and preserves unrelated lines.
- Each result is `verified`, `failed`, `offline`, `denied` or `notConfigured`.

## Remote design gate

Remote delivery will use Tailscale plus established age encryption. Each host gets its own recipient key and decrypts locally. The app will not invent a new encryption protocol. The remote helper must use allowlisted destinations and run a consumer-specific canary before reporting success.

## Never

- No arbitrary shell commands
- No request-provided path, environment variable or reload action
- No secrets in argv, receipts, stdout, stderr or diagnostic bundles
- No global-success result when any selected host is failed or offline
