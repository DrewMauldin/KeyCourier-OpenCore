# Specification: KeyCourier 1.1 to 1.6

## Objective

Complete KeyCourier as a private cross-device credential delivery system for
one owner. A model may request that an existing secret be installed or rotated,
but may never receive its plaintext. The MacBook remains the canonical secret
custodian. Mac Mini, VPS, provider and iPhone components receive only the
minimum encrypted material required for their role.

## Tech stack

- Swift and SwiftUI for macOS and iOS clients
- Security and LocalAuthentication for Keychain custody and user presence
- CryptoKit for device pairing, signatures and encrypted approval envelopes
- `age` for host-addressed encrypted delivery
- SSH over existing Tailscale aliases for private host transport
- XCTest with deterministic dummy values and protocol fakes
- XcodeGen for generated macOS and iOS targets

No hosted KeyCourier backend is introduced. Paired approval transport uses an
owner-controlled relay that stores opaque ciphertext only. The first supported
relay is iCloud/CloudKit private data; a local test relay proves the protocol
without requiring account state.

## Commands

```sh
xcodegen generate
xcodebuild -project KeyCourier.xcodeproj -scheme KeyCourierCore \
  -configuration Debug -derivedDataPath .derivedData \
  CODE_SIGNING_ALLOWED=NO build-for-testing
DYLD_LIBRARY_PATH="$PWD/.derivedData/Build/Products/Debug" \
  xcrun xctest ".derivedData/Build/Products/Debug/KeyCourierCoreTests.xctest"
./scripts/install-local.sh
```

Host and provider deployment commands must be scripted, idempotent, bounded to
an owner-approved profile and documented before execution. They must never put
secret values on argv or print credential-bearing files.

## Project structure

- `Sources/KeyCourierCore`: shared contracts, policies, lifecycle and adapters
- `Sources/KeyCourierApp`: native macOS custody and approval UI
- `Sources/KeyCourierCLI`: content-free agent interface
- `Sources/KeyCourierPhone`: native iPhone encrypted approval companion
- `HostAgent`: reviewed host helper sources and installation scripts
- `Tests/KeyCourierCoreTests`: unit, compatibility, recovery and fuzz guards
- `docs`: protocol, security, release and recovery specifications
- `tasks`: dependency-ordered implementation and verification checklist

## Release acceptance criteria

### 1.1: Cross-device delivery

- Distinct Mac Mini and VPS age identities are host-local and mode 600.
- An offline recovery recipient is stored outside the online host set and its
  restore procedure is tested with dummy material.
- Packages bind request ID, secret ID, target, consumer, creation and expiry;
  duplicate IDs fail before installation.
- Allowlisted adapters cover Mac Keychain, dotenv, Docker secrets, systemd
  credentials and launchd-managed services.
- Replacement is atomic, retains a protected previous version and runs only a
  fixed targeted reload action.
- A dummy request completes MacBook approval, encrypted transport, real
  consumer verification and a content-free receipt on both hosts.

### 1.2: Secret lifecycle

- Metadata records owner, rotation and expiry without storing values.
- The consumer map shows expected installation state for every secret.
- Rotation stages, verifies and commits a new version before retiring the old
  version; failure restores the protected previous version.
- Revocation disables one tuple without deleting the source secret.
- Content-free audits detect missing, stale and orphaned installations.
- Encrypted backup and offline recovery are tested with dummy material.
- Emergency lock prevents every new approval and delivery until the owner
  explicitly unlocks with user presence.

### 1.3: Agent ergonomics

- `doctor`, `consumers` and `secrets` expose diagnostics and identifiers only.
- Project aliases resolve only to owner-created request templates.
- Stable typed failure codes include content-free remediation.
- Retries are bounded and idempotent; offline outcomes are receipted.
- Codex, Claude Code and OpenCode integrations share the same request contract.
- Installer/update tooling is one command with rollback.
- Deep links select the exact pending request in the macOS app.

### 1.4: Approval policies

- Default is always ask.
- Once-only, short-window and standing policies are scoped to client, secret,
  consumer, target and action.
- Higher-risk destinations can require fresh user presence.
- Multi-destination requests show every destination and a blast-radius summary.
- Standing permissions expire and cannot introduce paths, commands or targets.

### 1.5: Reliability and security hardening

- Clients use dedicated signing keys or validated code-signing identities.
- Audit history is hash-chained, content-free and verifiable after export.
- Parsers have malformed, boundary and fuzz coverage.
- Host versions negotiate a compatible protocol or fail before decryption.
- Queues recover after interruption without duplicate delivery.
- Ownership and mode audits are available for every destination.
- Installer and updates are signed, verified and rollback-capable; notarisation
  and physical-device evidence remain explicit account gates.
- The iPhone companion receives an end-to-end encrypted request envelope and
  returns a signed, single-use approval. It never receives secret values.

### 1.6: Provider integrations

- n8n, GitHub Actions, Cloudflare, Vercel, SSH/certificate, database and
  application API-key adapters use narrow owner-created provider profiles.
- Provider adapters install or rotate directly and return content-free
  verification receipts.
- Short-lived credentials are preferred where the provider supports them.
- Each live provider path is enabled only after a dummy or account-safe canary.

## iPhone approval protocol

1. Pair the MacBook and iPhone in person using a one-time QR payload containing
   device identifiers and public keys. Each device keeps its private key in its
   local Keychain/Secure Enclave where supported.
2. The MacBook validates an incoming agent request, resolves owner-created
   profiles and creates a content-free approval envelope.
3. The MacBook encrypts the envelope to the paired iPhone and signs it. The
   relay stores only ciphertext, expiry and opaque routing identifiers.
4. The phone verifies the Mac signature and displays friendly names, reason,
   destinations, expiry and blast radius. It has no secret value to reveal.
5. Face ID confirms the owner action. The phone signs one approval or denial
   bound to the request hash, nonce and expiry, then encrypts it to the Mac.
6. The Mac verifies pairing, signature, expiry and one-time nonce. Only then
   does it ask the local Keychain for the secret and perform delivery.
7. Both devices store content-free, tamper-evident receipts. Replays, expired
   messages, unknown devices and mismatched request hashes fail closed.

If the iPhone or relay is offline, the request remains pending and the macOS
app can still perform its existing local owner approval. No approval silently
falls back to a weaker rule.

## Testing strategy

- Unit tests for every validation, policy and state transition
- Deterministic protocol vectors for encryption/signature compatibility
- Parser fuzz and size-bound tests
- Temporary-directory adapter tests that assert ownership, modes and rollback
- Host dummy canaries that verify consumers without printing values
- iOS Simulator accessibility and visual checks using semantic navigation
- Signed physical-device, provider-account and notarisation checks reported as
  external gates until live evidence exists

## Boundaries

- Always: preserve content-free observability, owner-created allowlists,
  restrictive permissions, expiry, replay protection and rollback.
- Ask first: adding a new provider scope, registering a new physical device,
  rotating a production credential or restarting a live service.
- Never: put secrets in Git, chat, argv, logs, receipts or relay records; infer
  a consumer path; run a general-purpose remote command; weaken a failed gate.

## Success criteria

Each release is tagged only after its own tests, build, dummy/live-safe canary,
documentation, rollback and installed runtime checks pass. A later release may
not be used to disguise an unverified earlier gate.
