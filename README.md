# KeyCourier

KeyCourier is a native macOS app with an iPhone companion that lets AI coding tools use approved
credentials without seeing their values. Codex, Claude Code and OpenCode ask
for a saved credential and destination. You approve the request on your Mac or,
for credentials you explicitly allow, through the paired iPhone or Telegram. KeyCourier installs the
credential directly and returns a content-free receipt.

[Public overview](https://keycourier.drewsdigest.com) · [Roadmap](ROADMAP.md) · [Architecture](docs/ARCHITECTURE.md)

![KeyCourier app icon](Design/KeyCourierIcon.png)

## Version 1.8

- Native SwiftUI app and menu-bar request queue
- Data-protection Keychain storage with user-presence access control
- Content-free `keycourier` CLI for agent requests and receipts
- Owner-created consumer allowlists
- Atomic mode-600 dotenv installation with one protected rollback copy
- Expiring requests, explicit approve/deny actions and content-free activity receipts
- Portable Agent Skill for Codex, Claude Code and OpenCode
- Guided This Mac, Mac Mini and VPS setup with stable built-in secret and destination mappings
- Fail-closed encrypted delivery to reviewed Mac Mini and VPS host agents
- One-click, content-free connection checks for both reviewed destinations
- Credential projects, environments, owners, rotation dates and expiry warnings
- Owner-approved `.env` import with values moved directly into Keychain
- Multi-recipient age-encrypted backup, recipient rekeying and offline restore
- Local notifications and optional replay-resistant Telegram approvals
- Friendly day-to-day screens with secret, consumer and target IDs kept under Advanced

## iPhone companion release candidate

- Native SwiftUI iPhone app for approval notifications, Face ID decisions and credential entry
- One-field key or password entry by default, with an optional username-and-password mode and in-place replacement
- One trusted iPhone paired through device keys, Mac owner authentication and a matching 48-bit verification code
- Private CloudKit records for Mac-signed request summaries and expiring, single-use signed decisions bound to exactly what the owner reviewed
- X25519 key agreement and ChaChaPoly encryption for credentials entered on the iPhone
- Mac-only decryption and import into the existing device-only Keychain service
- Per-credential opt-in for iPhone approval, with value re-entry required when changing the policy

The iPhone does not retain a credential vault. A value entered on the phone is
cleared from the form, encrypted to the verified Mac key and imported while the
Mac app is open and unlocked. AI clients still receive only the existing
content-free receipt.

On the Mac, a missing credential request now opens a compact protected prompt
with one **Paste key or password** field. Adding or replacing credentials uses
the same simple flow on both devices; names and other metadata stay optional.

| Destination | Current status |
|---|---|
| This Mac | Local owner-approved delivery is available |
| Mac Mini | Encrypted dummy canary passed; final app-mediated approval is pending |
| VPS | Encrypted dummy canary passed; final app-mediated approval is pending |

Production credentials remain disabled for the remote destinations until the
offline recovery identity has been moved off this Mac and the final canaries
have been approved in the app. Installing the native app on the Mac Mini also
requires an owner-authorised Apple signing profile.

## Optional Telegram approvals

1. Create a private bot with [BotFather](https://t.me/BotFather).
2. Open **Settings > Telegram approvals** in KeyCourier and save the bot token.
3. Send the displayed `/pair` command to the bot from your Telegram account.
4. Confirm the pairing in KeyCourier.
5. Edit each credential that may use Telegram, enable Telegram approval and
   enter its value again.

Pairing is limited to one private chat and user. Approval buttons expire and
can be used only once. Telegram receives the credential name, destination and
request reason, never the value or internal routing identifiers. Telegram Bot
API messages are not end-to-end encrypted, and delivery can complete only while
the Mac running KeyCourier is unlocked.

## Security boundary

Secret values enter through the app's `SecureField`, an explicitly selected
`.env` file or an explicitly selected encrypted recovery bundle. KeyCourier
does not enable Keychain synchronisation. The default Keychain mode uses
`kSecUseDataProtectionKeychain`,
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and user-presence access
control.

Telegram approval is opt-in for each credential. Enabling it requires entering
the value again and moves that item to a separate
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` Keychain service that only the
signed app uses. The paired Telegram chat and user, request expiry and a
single-use opaque nonce become the approval gate. Local approval for these
items still requires macOS owner authentication. Existing credentials remain
in the stronger default mode until explicitly changed.

Agents can handle these non-secret identifiers:

- secret ID
- target ID
- consumer ID
- request ID
- content-free receipt status and code

Agents must never handle the credential value. A request's client name is descriptive, not authenticated, because local AI clients run under the same macOS user. Owner approval and the consumer allowlist are the privileged boundary.

For the three built-in destinations, agents should use the short form:

```sh
keycourier request --client codex \
  --destination this-mac \
  --reason "Install the saved credential"
```

`--destination` accepts `this-mac`, `mac-mini` or `vps`. KeyCourier expands the friendly name to its stable secret, consumer and target IDs. `this-mac` installs to KeyCourier's private local dotenv destination after approval and does not require a network connection. The explicit-ID form remains available for custom destinations.

The Mac automation edition is intentionally unsandboxed so it can run the local CLI, use SSH and `age`, and write owner-approved files. It is distributed with Developer ID signing and notarisation. The separate sandboxed Mac App Store edition keeps credentials in Keychain and hands approved, encrypted commands to the notarised KeyCourier Bridge; it does not include Telegram approval, SSH, external `age`, or arbitrary file delivery inside the Store binary. KeyCourier does not attempt to protect against a process that has already compromised the macOS user account.

The public Mac app embeds the content-free CLI and reviewed agent skill under `Contents/Resources/Automation`. On Home, **Copy approved setup prompt** gives an AI assistant the exact bundled CLI path and the fail-closed setup rules, so customers do not need a separate command-line installation.

Telegram Bot API messages are not end-to-end encrypted. KeyCourier sends only
friendly request metadata and approval buttons, never credential values or
internal routing identifiers. The native iPhone companion is the end-to-end
encrypted remote approval option. Its private CloudKit records contain request
metadata, device public keys, signed decisions and encrypted credential
envelopes, never plaintext values.

## Build the iPhone companion

The source and simulator build are included in the `KeyCourierMobile` scheme.
Live pairing and push notifications require the Apple developer account to own
the `iCloud.com.drewsdigest.KeyCourier` container with CloudKit and remote
notification capabilities enabled for both app identifiers.

```sh
xcodegen generate
xcodebuild -project KeyCourier.xcodeproj \
  -scheme KeyCourierMobile -configuration Debug \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO build
```

## Install and launch

Requirements for a local development install: macOS 14 or later, Xcode 26 command-line tools, XcodeGen and an authorised Apple Development account configured in Xcode. The installer may register the current Mac with that development team when Xcode creates the provisioning profile.

```sh
./scripts/install-local.sh
```

The installer builds Release, requires an Apple Development identity for the configured signing team and installs `/Applications/KeyCourier.app`. It also installs `keycourier` under `~/.local/bin`, installs the canonical skill under `~/.agents/skills/keycourier`, links it for Claude Code, then launches the app. Existing app and skill installations are backed up before replacement.

If `~/.local/bin` is not on `PATH`, add it to the shell configuration used by your agents.

The agent-safe diagnostics expose identifiers and readiness only:

```sh
keycourier doctor
keycourier secrets
keycourier consumers
```

`doctor` performs read-only local protection and bounded host-reachability
checks. It never repairs configuration or reads a Keychain value.

## First local canary

1. In KeyCourier, add a secret with ID `keycourier-dummy` and value `dummy-not-a-real-secret`.
2. Add a consumer with ID `keycourier-local-canary`, target `this-mac`, a disposable absolute env path and variable `KEYCOURIER_DUMMY`.
3. Submit a request:

```sh
keycourier request --client codex \
  --secret-id keycourier-dummy \
  --target this-mac \
  --consumer keycourier-local-canary \
  --reason "Verify the local KeyCourier approval path"
```

4. Approve in the app using Touch ID or the Mac password.
5. Check `keycourier status REQUEST_ID`. Success is only `verified` plus `consumerVerified`.
6. Verify the consumer without printing the environment or credential value.

## Build and test

```sh
./scripts/verify-release.sh

# Or run the individual commands:
xcodegen generate
xcodebuild -project KeyCourier.xcodeproj \
  -scheme KeyCourierCore -configuration Debug \
  -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO build-for-testing
DYLD_LIBRARY_PATH="$PWD/.derivedData/Build/Products/Debug" \
  xcrun xctest "$PWD/.derivedData/Build/Products/Debug/KeyCourierCoreTests.xctest"
xcodebuild -project KeyCourier.xcodeproj \
  -scheme KeyCourier -configuration Release \
  -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO build
```

Public artifacts use the fail-closed workflows in
[the production-readiness specification](docs/SPEC-production-readiness.md).
They do not upload by default.

## Remote status

The Mac Mini and VPS now have distinct host recipients, reviewed owner-only
helpers, fixed dotenv canary consumers and a shared offline-recovery recipient.
Dummy ciphertext delivery, exact-package replay rejection, mode-600 consumer
verification and recovery decryption passed on 26 August 2026. The recovery
identity must still be moved from this Mac to owner-controlled offline media,
and the final app-mediated canary requires owner Touch ID.

See the [roadmap](ROADMAP.md), [architecture](docs/ARCHITECTURE.md),
[delivery specification](docs/SPEC-delivery.md) and
[personal vault and Telegram specification](docs/SPEC-personal-vault-and-telegram.md),
[implementation plan](tasks/plan.md).

The remote protocol implementation and remaining owner gates are documented in
[remote delivery](docs/REMOTE-DELIVERY.md).

## Rollback

The installer moves the previous app and client-skill installations into `~/Library/Application Support/KeyCourier/Install Backups` before replacing them. Quit KeyCourier, move the required timestamped backup back to its original location, and relaunch it. Vault entries are not deleted by an app rollback.

## Primary platform references

- [Apple data-protection Keychain](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)
- [Apple Keychain access-control flags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
- [Codex skills](https://developers.openai.com/codex/skills)
- [Claude Code skills](https://code.claude.com/docs/en/slash-commands)
- [OpenCode skills](https://opencode.ai/docs/skills)
