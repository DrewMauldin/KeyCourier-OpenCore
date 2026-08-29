# KeyCourier Mac App Store bridge specification

Last updated: 29 August 2026

## Decision

Ship three distinct products from one source repository:

1. **KeyCourier Automation** remains the current unsandboxed Developer ID app. Its bundle identifier, embedded CLI, SSH, external `age`, arbitrary owner-selected destinations and host-agent workflow remain unchanged.
2. **KeyCourier for Mac** is a sandboxed Mac App Store target. It owns credential entry, Keychain custody, request review, owner authentication, iPhone approvals, and release of a credential only into an encrypted bridge command. Telegram approval remains an Automation-edition feature and is not advertised for the App Store binary.
3. **KeyCourier Bridge** is a separately signed, notarised and open-source Developer ID app bundle containing the `keycourier-bridge` CLI. It owns LLM request transport, destination profiles and delivery. It never has Keychain access to the vault and never returns plaintext to its caller.

The App Store app and Automation app intentionally retain `com.drewsdigest.KeyCourier`. This preserves the existing App Store Connect record and makes Keychain continuity possible when Apple signing profiles authorise the existing access group. They are alternative editions and cannot be installed side by side. Keychain continuity must be proven with signed canaries before release.

The bridge uses `com.drewsdigest.KeyCourierBridge` and the macOS team-scoped App Group `T27WF6673W.com.drewsdigest.KeyCourier.bridge`.

## Caller view

The LLM calls a content-free interface:

```sh
keycourier-bridge request \
  --client codex \
  --secret-id example-key \
  --target this-mac \
  --consumer selected-env \
  --reason "Install the approved credential"

# {"requestID":"...","status":"pending"}

keycourier-bridge status REQUEST_ID

# {"requestID":"...","status":"verified",...}
```

The bridge rejects value-bearing options, approval commands, arbitrary shell commands and destination paths supplied at request time. LLM output is untrusted metadata. A request never authorises itself.

The bridge may also expose content-free `secrets`, `consumers` and `doctor` commands. Secret names and destination names are explicitly non-secret product metadata. Credential values, ciphertext, private keys, raw destination files and environment contents must never be printed.

## Public shape

```swift
public struct BridgeRegistration: Codable, Sendable {
    public let schemaVersion: Int
    public let bridgeID: UUID
    public let displayName: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data
    public let bridgeNonce: Data
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data
}

public struct BridgePairingProposal: Codable, Sendable {
    public let schemaVersion: Int
    public let bridgeID: UUID
    public let registrationDigest: Data
    public let appSigningPublicKey: Data
    public let appNonce: Data
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data
}

public struct BridgeTrustGrant: Codable, Sendable {
    public let schemaVersion: Int
    public let bridgeID: UUID
    public let registrationDigest: Data
    public let proposalDigest: Data
    public let grantedAt: Date
    public var signature: Data
}

public struct SignedBridgeRequest: Codable, Sendable {
    public let schemaVersion: Int
    public let bridgeID: UUID
    public let request: SecretRequest
    public let requestNonce: Data
    public var signature: Data
}

public enum BridgeOwnerAction: String, Codable, Sendable {
    case deliver
    case deny
}

public struct BridgeDeliveryCommand: Codable, Sendable {
    public let schemaVersion: Int
    public let commandID: UUID
    public let bridgeID: UUID
    public let requestID: UUID
    public let requestDigest: Data
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let action: BridgeOwnerAction
    public let ephemeralPublicKey: Data?
    public let ciphertext: Data?
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data
}

public struct SignedBridgeReceipt: Codable, Sendable {
    public let schemaVersion: Int
    public let bridgeID: UUID
    public let commandID: UUID
    public let requestDigest: Data
    public let receipt: RequestReceipt
    public var signature: Data
}
```

Every signing payload uses a type-specific `KeyCourier.Bridge.*.v1` domain, fixed millisecond dates and length-prefixed fields. Transport JSON is never the signing representation.

The public interface stays small:

```swift
public protocol BridgeCallerServing: Sendable {
    func submit(_ request: SecretRequest) throws -> UUID
    func receipt(for requestID: UUID) throws -> RequestReceipt?
}

public protocol BridgeOwnerServing: Sendable {
    func registrations() throws -> [BridgeRegistration]
    func pair(_ registration: BridgeRegistration) throws -> BridgePairingProposal
    func trust(_ grant: BridgeTrustGrant) throws
    func pendingRequests() throws -> [SignedBridgeRequest]
    func enqueue(_ command: BridgeDeliveryCommand) throws
    func receipts() throws -> [SignedBridgeReceipt]
}
```

Callers do not coordinate file names, queue layout, canonical encoding, replay markers or cryptography.

## Pairing

1. The bridge creates an Ed25519 signing key and X25519 agreement key in its private Keychain. It writes a self-signed registration with 32-byte nonce and a five-minute expiry.
2. The Store app validates the registration and writes a signed proposal containing its Ed25519 public key and a separate 32-byte nonce.
3. Both sides calculate the same grouped hexadecimal pairing code from both public keys, both nonces and both record digests.
4. The bridge displays the code. The Store app requires the owner to confirm that the codes match and then pass explicit owner authentication before writing the trust grant.
5. The bridge requires a separate macOS owner-authentication prompt displaying the same code before it accepts the grant. A caller cannot establish trust by replaying the code as a CLI argument.
6. Each side pins the other signing key in its private Keychain. The Store app also pins the bridge agreement key.

App Group membership and file ownership are transport controls, not authentication. A message is trusted only after signature verification against the pinned peer key.

Pairing, key rotation and bridge removal purge pending requests, commands, receipts, snapshots and replay markers before changing trust. They never migrate or share vault Keychain items.

## Request and delivery flow

1. `keycourier-bridge request` parses the existing allowlisted request flags, validates `SecretRequest`, signs it and atomically writes it to the shared request queue.
2. The bridge runs `/usr/bin/open -b com.drewsdigest.KeyCourier` with no payload. The Store app also polls while running.
3. The Store app validates size, schema, identifiers, dates, signature, pinned bridge identity and replay state before displaying metadata.
4. Approval requires the existing owner-presence boundary. The app reads the credential from its private Keychain only after validation and owner approval.
5. For delivery, the app derives an ephemeral X25519 shared secret with the pinned bridge agreement key. ChaChaPoly uses an HKDF-SHA256 key with a bridge-specific salt and command ID shared info. The authenticated payload binds the secret to the exact request digest, target, consumer, bridge and expiry.
6. The app signs and atomically writes the ciphertext command, then clears plaintext memory as soon as Swift ownership permits. Denial writes the same signed command shape without ciphertext.
7. The bridge verifies the app signature, request digest, bridge ID, target, consumer, expiry and replay state before decrypting. It resolves a previously allowlisted destination profile. Request-time metadata cannot create or alter a destination.
8. The bridge decrypts only in process memory, resolves a separately owner-approved local dotenv profile and writes a signed content-free receipt. Single values map to one allowlisted variable; username/password credentials map to two distinct allowlisted variables. Stdout, stderr, queue files and logs never contain the value. Existing remote delivery is excluded until the remote package authenticates its sender as well as encrypting its contents.
9. The Store app verifies and records the receipt before removing the request and command. The CLI returns only the receipt.

## Transport and storage

The App Group is a durable, no-daemon queue. The URL launch is wake-up only.

```text
Pairing/Registrations/
Pairing/Proposals/
Pairing/Grants/
Requests/
Commands/
Receipts/
Snapshots/
Claims/
```

Rules:

- directories are owner-controlled and mode 700 where macOS permits;
- regular files are mode 600, opened with no-follow semantics and size-capped;
- writes are temp-file, `fsync`, mode-check and atomic rename;
- exclusive queue publication never exposes an empty placeholder record;
- file names are derived only from validated UUIDs and fixed suffixes;
- maximum 100 pending records per active queue and 400 total records;
- requests and commands expire within 24 hours, with a 15-minute default;
- pairing records expire within five minutes;
- duplicate ID plus identical digest is idempotent;
- duplicate ID plus different digest is rejected as tampering;
- claims are exclusive replay markers and are retained for at least the full capability lifetime;
- unknown or malformed files are ignored for display and reported as a content-free health failure;
- no queue file contains plaintext, private keys, Telegram tokens, recovery identities or complete destination configuration.

The bridge keeps destination profiles and its delivery replay state under `~/Library/Application Support/KeyCourierBridge`, not in the App Group. The Store app publishes only signed content-free credential and destination summaries for CLI discovery.

## Failure behaviour

- Missing or unpaired bridge: the Store app never reads a credential and the CLI reports unavailable.
- Invalid, oversized, expired, tampered or replayed request: reject before owner prompting.
- Bridge unavailable after approval: retain the sealed command until expiry and report pending/offline.
- Profile digest, target or consumer mismatch: reject before decryption.
- Crash before a command claim: safe retry.
- Crash after a claim with no receipt: report an unknown outcome and require a fresh owner-approved capability. Never retry a credential write or create a new request implicitly.
- Unsafe destination, SSH, `age` or host failure: signed content-free failed receipt.
- Unknown delivery state: re-read the same command and receipt state. Never report verified without destination confirmation.
- Store and Automation queues never fall back into each other.

## Module map

- `KeyCourierCore/BridgeProtocol.swift`: records, canonical payloads, validation, signing, sealing and opening.
- `KeyCourierCore/BridgeQueue.swift`: injected-root queue, bounds, atomic persistence and replay claims.
- `KeyCourierCore/BridgeStorage.swift`: App Group resolution, private per-product Keychain identities and pinned peer keys.
- `KeyCourierStoreApp`: Store-owned credential entry, pairing, request review, owner-authenticated approval, encrypted dispatch, receipt reconciliation and unpair UI.
- `KeyCourierBridge`: CLI pairing, separately owner-approved dotenv destination profiles, request submission, one-shot/background delivery, reset and content-free status.
- `project.yml`: separate `KeyCourierStore` and `KeyCourierBridge` targets and schemes. The existing targets remain unchanged.

## Entitlements and packaging

Store target:

- App Sandbox enabled;
- `T27WF6673W.com.drewsdigest.KeyCourier.bridge` App Group;
- network client;
- production CloudKit and current vault Keychain group;
- no network server, executable file access, SSH, external `age`, CLI installation or LaunchAgent installation.

Bridge target:

- Developer ID Application and hardened runtime;
- the same team-scoped App Group;
- a bridge-private Keychain identity only;
- no vault Keychain access group and no App Sandbox;
- notarised app bundle with a stable CLI path and optional user-local symlink installed outside the Store app.

Apple documents that same-team macOS processes can share a team-prefixed App Group without registering or provisioning that group. App Sandbox is mandatory for the Store target. Restricted Keychain groups still require correctly matched distribution profiles.

## Alternatives considered

- **Named XPC LaunchAgent** has stronger live peer authentication, but adds a persistent daemon, installer, launchd lifecycle and App Store mach-service configuration before the product proves the bridge boundary.
- **Signed custom URLs** avoid a shared group, but custom schemes are hijackable, have awkward payload limits and force either the sandboxed app to perform restricted delivery or a second callback transport.
- **Security-scoped destinations in the Store app** are self-contained, but require recurring owner file grants and cannot preserve SSH or host delivery.
- **Shared Keychain** gives the bridge standing vault access and is prohibited.
- **Plaintext files or XPC** unnecessarily broaden plaintext lifetime and are prohibited.
- **CloudKit local IPC** adds account, network, quota and latency failure modes without improving local owner approval.

`SecureFileSystem` now performs boundary operations through directory descriptors using `openat`, `renameat`, `O_NOFOLLOW`, post-open `fstat`, link-count checks and file plus directory `fsync`. The remaining same-UID replacement races are outside the trust provided by App Group transport and do not replace signature verification against pinned peer keys.

## Current implementation status

The repository contains the isolated Store and Bridge targets, signed pairing records, explicit code confirmation, owner-authenticated trust, pinned peer keys, authenticated metadata-only requests, bounded crash-safe queues, encrypted command primitives and content-free receipt primitives.

The source now implements the complete local request, owner approval, encrypted command, allowlisted dotenv delivery and signed receipt path. It also rejects completed-command replay, binds claims to canonical records, supports owner-authenticated reset on both products, propagates Store unpair through a signed content-free Bridge revocation and fails closed when queue cleanup is unsafe.

This remains a production candidate rather than a released binary. Current Apple distribution profiles, signed App Group/Keychain continuity, notarisation, Store processing and physical-device canaries remain independent release gates.

## Verification

- bridge protocol round-trips and deterministic signing payloads;
- altered field, wrong key, wrong recipient, expired and replay failures;
- pairing code changes for either key, nonce or digest;
- ciphertext JSON and all queue files exclude a canary value;
- bounded queue, symlink, ownership, file type, permission and conflicting-ID tests;
- crash/retry and one-delivery idempotency tests;
- fake owner authoriser proves no Keychain read before approval;
- local dummy dotenv end-to-end canary;
- remote delivery tests remain injected until a physical signed canary;
- Store build proves App Sandbox and excludes embedded CLI, SSH and `age` execution paths;
- Bridge build proves distinct bundle ID, no vault access group, hardened runtime and Developer ID signing;
- existing Automation and iPhone builds and all Core tests remain green.

## First vertical slice

The implemented first slice proves:

```text
keycourier-bridge request
  -> Store owner approval
  -> encrypted command
  -> Bridge dummy install
  -> verified content-free receipt
```

No plaintext may appear in request files, command metadata, receipts, logs, CLI output or App Group snapshots.
