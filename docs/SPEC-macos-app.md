# Spec: KeyCourier macOS app

## Objective

Create a private native macOS app for Drew to store named credentials, review AI requests and approve delivery to explicit consumer profiles.

## Tech stack

- SwiftUI and Observation, macOS 14+
- Security framework using the data-protection Keychain
- LocalAuthentication-backed user presence
- XcodeGen-generated Xcode project
- No hosted service and no analytics

## Commands

Use the generate, build and test commands in `SPEC-request-contract.md`.

## Project structure

The UI is organised by feature under `Sources/KeyCourierApp`, while policy and persistence remain in `KeyCourierCore` so they are independently testable.

## Code style

```swift
@MainActor
@Observable
final class AppModel {
    private(set) var requests: [SecretRequest] = []
    private(set) var secrets: [SecretMetadata] = []
}
```

Views own only presentation state. `AppModel` coordinates use cases. Secret values remain local variables for the shortest practical lifetime and never enter observable state outside the entry form.

## Testing strategy

- Core behaviour is tested without SwiftUI or the system Keychain.
- The app must compile as a native application target.
- A manual dummy-secret canary must prove entry, Keychain retrieval prompt, approval and content-free receipt before real secrets are used.

## Boundaries

- Always: show client, target, consumer, reason and expiry before approval; require fresh user presence for retrieval; clear entry fields after storage.
- Ask first: enable App Sandbox exceptions, install login items, add remote agents or distribute signed builds.
- Never: reveal stored values in the UI after save; add copy buttons; place secrets in `UserDefaults`, SwiftData, JSON or logs.

## Success criteria

- An owner can store, list and delete named credentials.
- Pending requests are visible from the menu bar and main window.
- Approval fails if the request is expired, the secret is missing, the consumer is not allowlisted or the target is unavailable.
- Denial and approval generate content-free receipts.

## Open questions

Live Mac Mini and VPS installation remain gated on the dummy-secret local canary.
