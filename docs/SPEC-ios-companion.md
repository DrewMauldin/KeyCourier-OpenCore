# Specification: native iPhone companion

## Objective

Let the owner receive KeyCourier approval notifications, approve or decline an
eligible request with Face ID, and add an API key or password from an iPhone
without exposing a plaintext credential to CloudKit, an AI client, a receipt or
another unpaired device.

## Caller view

### Pair the phone

1. Enable **iPhone companion** in the Mac app.
2. Register the iPhone in the mobile app.
3. Approve that exact registration on the Mac using owner authentication.
4. Compare the 48-bit verification code shown by both apps.
5. Confirm the match on the iPhone using Face ID or device passcode.

Only one iPhone can be trusted at a time. Replacing it requires removing the
existing trust on the Mac and approving a new registration.

### Approve a request

1. An AI client submits the existing identifier-only request through the local
   file inbox.
2. The Mac publishes a friendly summary only when that credential explicitly
   allows iPhone approval.
3. CloudKit notifies the iPhone that a request record changed.
4. The owner reviews the credential name, destination, client, reason and
   expiry, then authenticates with Face ID or device passcode.
5. The iPhone writes a signed five-minute decision.
6. The Mac verifies device ID, signature, expiry, replay state and the local
   credential policy before calling the existing `ApprovalCoordinator`.
7. The requesting client receives the existing content-free receipt.

### Add or replace a credential

1. The owner pastes one API key or password. They can instead choose the
   bounded username-and-password format. A display name is optional and kept
   under **Advanced**.
2. Replacing an existing credential starts in its current format and requires
   no metadata form.
3. The iPhone authenticates the owner.
4. The iPhone creates an ephemeral X25519 key and derives a symmetric key with
   the verified Mac public key using HKDF-SHA256.
5. The value and metadata are encrypted with ChaChaPoly and the envelope is
   signed by the paired phone.
6. The plaintext form fields are cleared before upload.
7. The Mac verifies, decrypts and imports or replaces the value in its
   device-only, approval-gated Keychain service while KeyCourier is open and
   unlocked.

### Satisfy a missing credential request on the Mac

1. An AI client submits the existing identifier-only request.
2. If the credential is missing, the running Mac app activates its main window
   and shows one protected **Paste key or password** field.
3. The owner can optionally switch to username and password, then saves once.
4. KeyCourier stores the value and continues the normal owner-approved request
   flow. The AI client never receives the plaintext.

The phone does not retain a plaintext credential vault.

## Public shape

```swift
protocol CompanionCloudServing: Sendable {
    func saveDeviceRegistration(_ registration: CompanionDeviceRegistration) async throws
    func replaceRequests(_ requests: [CompanionRequestSummary]) async throws
    func saveDecision(_ decision: CompanionDecision) async throws
    func saveSecretEnvelope(_ envelope: CompanionSecretEnvelope) async throws
}

enum CompanionCrypto {
    static func sign(
        _ decision: CompanionDecision,
        keys: CompanionPrivateKeys
    ) throws -> CompanionDecision

    static func seal(
        _ payload: CompanionSecretPayload,
        deviceID: UUID,
        recipientPublicKey: Data,
        signingKeys: CompanionPrivateKeys
    ) throws -> CompanionSecretEnvelope
}
```

CloudKit record types remain behind `CompanionCloudServing`. SwiftUI views do
not construct records, signatures or encryption keys.

## Ownership and persistence

| Asset | Owner | Persistence |
|---|---|---|
| Mac private device key | Mac app | Device-only data-protection Keychain |
| iPhone private device keys | iPhone app | Device-only data-protection Keychain |
| Trusted phone public keys | Mac app | Mode-600 companion configuration |
| Verified Mac public key | iPhone app | Device-only data-protection Keychain |
| Request summary | Mac app | Private CloudKit database, bounded and expiring |
| Approval decision | iPhone app | Private CloudKit database until consumed |
| Credential envelope | iPhone app | Private CloudKit database until imported |
| Credential plaintext | Mac app | Existing device-only Keychain service |
| Replay markers | Mac app | Mode-600 bounded companion configuration |

## Threat model

### Assets

- credential plaintext
- authority to approve a fixed delivery
- Mac and iPhone private device keys
- the local consumer allowlist

### Trust boundaries

- local AI request file to the Mac app
- Mac app to private CloudKit records
- CloudKit notification to the iPhone app
- iPhone decision or credential envelope back to the Mac app
- decrypted credential to the existing allowlisted installer

### Abuse cases and controls

| Abuse case | Control |
|---|---|
| Substitute a Mac encryption key in CloudKit | Owner compares the code derived from both device keys before the phone persists trust |
| Forge or edit a decision | Ed25519 signature covers request, device, action and exact expiry |
| Replay a valid decision | Five-minute expiry, local processed-ID ledger and CloudKit deletion |
| Upload a credential from another device | Envelope device ID and signature must match the one locally trusted phone |
| Decrypt a CloudKit envelope | X25519 recipient is the verified Mac device key; value is inside ChaChaPoly ciphertext |
| Approve an ineligible credential | Mac publishes and accepts only metadata with `allowsCompanionApproval` |
| Bypass the consumer allowlist | Mac reuses `ApprovalCoordinator`; the request still cannot select an arbitrary path or command |
| Flood private records | Each record type is bounded to 200 and field sizes are validated before use |

## Failure behaviour

- No iCloud account: pairing and relay operations fail closed with a user-facing
  configuration error.
- Mac closed or locked: decisions and encrypted credential envelopes wait in
  the private database until they expire or the Mac can process them.
- Invalid signature, wrong device, expiry or replay: the Mac rejects the action,
  records its ID and does not read a credential.
- CloudKit push coalescing: the iPhone treats a notification as a refresh hint
  and fetches the complete bounded request set.
- Existing secret ID: the Mac accepts replacement only when that credential is
  explicitly eligible for companion use; otherwise it rejects the envelope.

## Verification

Automated:

- decision signature success, tampering and expiry
- encrypted credential round trip and wrong-recipient rejection
- pairing code changes when the Mac key changes
- companion trust and replay configuration round trip
- existing request, Keychain, Telegram, remote delivery and receipt regressions
- unsigned macOS and iOS Simulator builds

Physical-device release gates:

- signed Mac and iPhone targets use the same production CloudKit container
- development schema is promoted to production before TestFlight
- pairing code matches on the two real devices
- visual notifications work with the app foregrounded, backgrounded and
  terminated
- dummy approve, deny and encrypted credential import complete end to end
- a replayed decision and a ciphertext for another Mac fail closed

## Alternative rejected

Direct iCloud Keychain synchronisation would be smaller, but it would silently
change existing credentials from device-only custody to synchronised custody.
A hosted API would add another operator, authentication flow, database and
breach surface. The selected private CloudKit metadata relay plus app-level
cryptography preserves the current Mac delivery authority with no new hosted
backend.
