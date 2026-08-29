# Changelog

All notable changes to KeyCourier are documented here.

## 1.8.0 - 2026-08-28

### Added

- Added the native `KeyCourierMobile` SwiftUI companion target for private
  approval notifications, Face ID approval and denial, and secure API key or
  password entry.
- Added one-device iPhone pairing with Mac owner authentication and a matching
  out-of-band verification code before the phone can approve or send a value.
- Added a private CloudKit relay for friendly request summaries, signed
  decisions and encrypted credential envelopes.
- Added per-credential iPhone approval policy and Mac-side processing that
  reuses the existing allowlisted delivery coordinator.
- Added compact add and replacement flows on Mac and iPhone: one protected key
  or password field by default, with an optional username-and-password mode.
- Added automatic Mac presentation of the compact prompt when an AI client
  requests a credential that has not been saved yet.

### Security

- Phone decisions are Ed25519-signed, expire after five minutes and are kept in
  the existing bounded replay ledger after consumption.
- Phone-entered values use ephemeral X25519 key agreement, HKDF-SHA256 and
  ChaChaPoly. Only the verified Mac device key can decrypt them.
- Existing device-only credentials do not become phone-approvable unless the
  owner explicitly re-enters the value and changes that credential's policy.

## 1.7.1 - 2026-08-27

### Changed

- Replaced the original detailed vault artwork with the owner-approved blue Courier Route icon and regenerated every native macOS icon size.

## 1.7.0 - 2026-08-26

### Added

- Added This Mac as a first-class destination with its own Keychain-backed secret, registered private local consumer and `--destination this-mac` agent shortcut.
- Added guided Mac Mini and VPS secret slots with idempotent built-in consumer registration.
- Added the `--destination mac-mini|vps` agent shortcut while retaining explicit-ID requests.
- Reworked the native app around Home, Requests, History and Advanced so internal routing names stay out of the primary flow.
- Enforced the 100-item pending request inbox limit at submission time.
- Added a dependency-injected remoteAge protocol with fixed profiles, age
  encryption adapters, request/expiry/replay validation, atomic consumer
  installation and content-free remote receipts.
- Documented the host helper and recipient installation plan; live host
  delivery remains disabled pending owner review and dummy canaries.
- Added a one-click Mac Mini and VPS connection test that validates host
  readiness without sending a credential or changing a consumer.
- Added project, environment and owner grouping with rotation and expiry health.
- Added bounded `.env` import that moves selected values into Keychain without
  retaining the source file or path.
- Added multi-recipient age recovery exports, recipient rekeying and offline
  restore with whole-bundle validation.
- Added local request and delivery notifications.
- Added optional per-credential Telegram approvals paired to one private chat
  and user with expiring, single-use opaque callbacks.
- Moved secret, consumer and target identifiers into Advanced disclosures and
  added generated friendly identifiers for normal setup.

### Security

- Telegram never receives secret values or internal routing identifiers.
- Telegram-capable credentials require an explicit re-entry and use a separate
  approval-gated, device-only Keychain service.
- Telegram bot tokens are stored in a dedicated device-only Keychain item and
  never written to metadata.

## 1.0.0 - 2026-08-26

### Added

- Native SwiftUI app and menu-bar approval queue.
- Data-protection Keychain storage requiring user presence for reads.
- Content-free CLI requests and receipts for Codex, Claude Code and OpenCode.
- Owner-managed consumer allowlists and atomic dotenv installation with rollback.
- Strict request validation, expiring requests and fail-closed remote destinations.
- Portable agent skill, accessibility audit and local signed installer.

### Security

- Secret values never appear in agent requests, receipts, metadata or activity records.
- Keychain synchronisation is disabled and local support files are owner-only.
- Mac Mini and VPS delivery remains unavailable until per-host helpers pass dummy-secret canaries.
