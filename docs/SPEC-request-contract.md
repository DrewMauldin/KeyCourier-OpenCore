# Spec: KeyCourier request contract

## Objective

Provide a small, content-free interface that an AI coding client can use to ask Drew to provision or use a named secret. The interface must never accept, persist or return secret values.

## Tech stack

- Swift 6 compiler in Swift 5 language mode
- Foundation `Codable`
- Atomic JSON files under a mode-700 application-support directory
- No third-party packages

## Commands

- Generate: `xcodegen generate`
- Build: `xcodebuild -project KeyCourier.xcodeproj -scheme KeyCourier -configuration Debug -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO build`
- Test: `xcodebuild -project KeyCourier.xcodeproj -scheme KeyCourier -configuration Debug -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO test`
- Submit request: `.derivedData/Build/Products/Debug/keycourier request --client codex --secret-id example-key --target this-mac --consumer local-example --reason "Configure the example consumer"`
- Inspect request: `.derivedData/Build/Products/Debug/keycourier status REQUEST_ID`

## Project structure

- `Sources/KeyCourierCore`: types, validation, persistence and delivery policies
- `Sources/KeyCourierApp`: native SwiftUI application
- `Sources/KeyCourierCLI`: content-free command-line client
- `Tests/KeyCourierCoreTests`: pure and temporary-directory tests
- `docs`: security, architecture and integration documentation
- `tasks`: implementation plan and verification checklist

## Code style

```swift
public struct SecretID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(validating rawValue: String) throws {
        self.rawValue = try IdentifierValidator.validate(rawValue)
    }
}
```

Use explicit domain names, value types at trust boundaries, injected stores for side effects, and no logging of raw request payloads.

## Testing strategy

- Unit tests prove identifier validation, request expiry and content-free receipt encoding.
- Integration tests use temporary directories to prove file modes, atomic persistence and dotenv replacement.
- The Keychain implementation is isolated behind `SecretStore`; automated tests use an in-memory fake and a manual dummy-secret canary verifies the real system Keychain.

## Boundaries

- Always: validate decoded requests; cap field lengths; write directories mode 700 and files mode 600; use atomic replacement.
- Ask first: add destinations, network transports, background launch agents or new dependencies.
- Never: accept secret material in requests; return plaintext; execute request-provided commands; use request-provided filesystem paths; log request bodies.

## Success criteria

- Invalid, expired, oversized and unknown-version requests fail closed.
- Valid requests can be submitted and listed without opening a network listener.
- Receipts contain identifiers and status only, with no secret-bearing field.
- The CLI never accepts a `value`, `password`, `token` or `secret` argument.

## Open questions

None for V1.
