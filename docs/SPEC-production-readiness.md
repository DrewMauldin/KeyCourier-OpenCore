# Spec: KeyCourier production readiness

## Objective

Prepare the current KeyCourier source for a public production beta without weakening its central security boundary: an LLM may request an operation, but only the owner enters or approves a credential and the LLM never receives plaintext.

This release work covers:

- a Developer ID signed and notarised Mac automation edition;
- a sandboxed Mac App Store edition that delegates approved delivery to the separately notarised KeyCourier Bridge;
- an iPhone App Store companion using the private production CloudKit container;
- public source, security, privacy, support and release documentation;
- repeatable unsigned verification plus fail-closed signed archive workflows;
- an explicit record of Apple account and physical-device evidence that cannot be proven from source.

The automation and App Store editions are separate targets. The automation edition intentionally runs local automation, SSH and `age`, installs a CLI and host helpers, and writes to owner-approved destinations outside an app container. The App Store edition is sandboxed, keeps the vault and owner approval on the Mac, and delegates content-free request transport and approved encrypted delivery to the separately distributed KeyCourier Bridge.

## Tech stack

- Swift 5 and SwiftUI
- macOS 14 or later
- iOS 17 or later, iPhone only
- Security, LocalAuthentication, CryptoKit, CloudKit and UserNotifications
- XcodeGen and Xcode 26
- Python 3 host-agent tests

## Commands

```sh
# Deterministic repository verification without signing
./scripts/verify-release.sh

# Prepare a Developer ID Mac archive without uploading
./scripts/archive-mac-developer-id.sh

# Explicitly submit that artifact to Apple notarisation
./scripts/archive-mac-developer-id.sh --notarize

# Prepare an iPhone App Store archive and local export without uploading
./scripts/archive-ios-app-store.sh
```

The signed archive commands must stop with a specific remediation when the required Apple certificate, provisioning profile, CloudKit capability or notarisation Keychain profile is missing. They must never invent credentials, enable a capability or upload a build implicitly.

## Project structure

- `Sources/KeyCourierCore`: request, Keychain, delivery and lifecycle boundaries
- `Sources/KeyCourierApp`: native Mac automation edition
- `Sources/KeyCourierMobile`: native iPhone companion
- `Sources/KeyCourierCompanionShared`: bounded CloudKit and cryptographic protocol
- `Tests/KeyCourierCoreTests`: Core and shared protocol tests
- `HostAgent/tests`: allowlisted remote consumer tests
- `scripts`: verification, archive, packaging and local installation workflows
- `metadata`: reviewed App Store copy and screenshot inventory
- `docs`: threat model, release evidence, privacy and recovery guidance

## Code style

Prefer small validating initialisers and fail-closed guards at trust boundaries:

```swift
guard request.deviceID == trustedDevice.registration.id,
      request.expiresAt > now else {
    throw CompanionProtocolError.invalidRecord
}
```

Secret values must not be interpolated into strings, errors, logs, notifications, command arguments, receipts or metadata.

## Testing strategy

- Unit tests cover identifiers, size limits, expiry, replay, signatures, encryption, tamper rejection, metadata compatibility and allowlisted installation.
- The full release verifier builds the Core test bundle, runs Core/shared tests, runs host-agent tests, builds the Mac Release target and builds the iPhone Release simulator target.
- Signed artifact verification inspects entitlements, hardened runtime, certificate class and embedded provisioning before packaging.
- Physical-device verification covers pairing, foreground/background/terminated notification delivery, approve, deny, encrypted credential import and replay rejection with dummy values only.
- Production CloudKit, App Store processing and notarisation are reported as external evidence, never inferred from a simulator or unsigned build.

## Boundaries

### Always

- Preserve existing credentials and unrelated dirty-worktree changes.
- Use dummy values for tests and canaries.
- Keep source verification distinct from signed artifact and live-service proof.
- Keep release output outside the source tree or under an ignored build directory.
- Verify privacy/support links and archive metadata before submission.

### Ask first

- Create or change an App Store Connect app record or bundle identifier.
- Promote a CloudKit schema or enable Apple capabilities.
- Upload to TestFlight, notarisation or App Review.
- Publish a website, source release, tag or paid product.
- Replace the installed app or run a live credential delivery canary.
- Choose the final open-source licence without owner or legal approval.

### Never

- Put credentials, private keys, provisioning files or notarisation credentials in Git.
- Expose plaintext to an LLM, receipt, notification, analytics system or support report.
- Treat development signing, simulator builds or local HTTP responses as production proof.
- Claim Mac App Store eligibility for the unsandboxed automation target.

## Success criteria

- `./scripts/verify-release.sh` passes from the intended source state.
- Mac and iPhone Release builds contain the expected production entitlements and privacy metadata.
- Developer ID and App Store archive scripts are repeatable, non-uploading by default and fail closed without owner-held signing state.
- There are no unresolved reachable critical or high security findings in repository-controlled code.
- Security, privacy, support, recovery, release and App Review instructions match the implemented behaviour.
- A reviewed App Store metadata package and screenshot inventory exist without creating an App Store record.
- The source distribution has a reviewed licence decision, contribution policy, vulnerability-reporting path, notices and trademark boundary.
- Every remaining external gate names the exact owner action and evidence required.

## External completion gates

- Confirm the product model: universal purchase with a future sandboxed Mac edition, or a paid Developer ID Mac app with a separate companion.
- Record the owner-approved MPL-2.0 licence and its source, artwork and trademark boundary. Seek legal advice before changing that boundary.
- Verify the Apple identifiers and capabilities without merging or recreating records blindly.
- Promote the production CloudKit schema.
- Produce and inspect Apple Distribution and Developer ID archives.
- Complete export-compliance and App Privacy answers in App Store Connect.
- Pass physical two-device canaries.
- Complete an independent security review.
- Upload, process and review builds only after the above evidence is green.
