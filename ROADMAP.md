# KeyCourier roadmap

KeyCourier is being developed as a private, owner-controlled credential broker.
The roadmap is ordered by dependency, not by promised date. A release advances
only after its real consumer path has passed with a dummy value.

## Status

| Release | State | Outcome |
|---|---|---|
| 1.1 | In progress | Complete cross-device delivery |
| 1.2 | In progress | Secret lifecycle management |
| 1.3 | Started early | Better agent ergonomics |
| 1.4 | Planned | Scoped approval policies |
| 1.5 | Planned | Reliability, security and iPhone approval |
| 1.6 | Planned | Direct provider integrations |

## Current private build

- The signed native macOS app runs on the MacBook.
- This Mac is available as a local, owner-approved destination.
- The Mac Mini and VPS have distinct `age` recipients and reviewed host helpers.
- Dummy ciphertext delivery, replay rejection, mode-600 consumer verification
  and recovery decryption have passed on both remote hosts.
- The CLI, agent skill and receipts expose identifiers and status only.

Before remote production credentials are enabled, the recovery identity must be
moved to owner-controlled offline media and the final app-mediated canary must
be approved with Touch ID. Native installation on the Mac Mini also depends on
an owner-authorised Apple signing profile.

## 1.1: Complete cross-device delivery

- Complete the final owner-approved canary on the Mac Mini and VPS.
- Move and test the offline recovery identity.
- Finish allowlisted adapters for macOS Keychain, dotenv files, Docker secrets,
  systemd credentials and launchd-managed services.
- Add atomic replacement, protected rollback and targeted service reloads.
- Keep production delivery locked until each exact consumer passes a dummy
  canary.

Success means: request on the MacBook, owner approval, encrypted delivery, real
consumer verification and a content-free receipt.

## 1.2: Secret lifecycle management

Available now:

- Track owners, projects, environments, rotation dates and expiry warnings.
- Show a credential lifecycle dashboard without reading values.
- Export and restore an age-encrypted multi-recipient recovery bundle.
- Rekey recovery by replacing public recipients and exporting a fresh bundle.

Still planned:

- Show where each secret is installed without reading its value.
- Add two-phase rotation so dependent services do not break mid-change.
- Revoke one host or consumer without deleting the source secret.
- Detect stale, missing and orphaned installations using metadata.
- Test offline recovery with the owner-held identity and add an emergency delivery lock.

## 1.3: Better agent ergonomics

Already available:

- `keycourier doctor`, `keycourier secrets` and `keycourier consumers`
- identifier-only requests and content-free receipts
- one-command local app, CLI and skill installation
- friendly built-in names for This Mac, Mac Mini and VPS

Still planned:

- project aliases such as `second-brain-production`
- typed failure codes with specific remediation
- bounded retries and offline receipt recovery
- approval links that open the exact request in KeyCourier
- first-class, updateable integrations for Codex, Claude Code and OpenCode

## 1.4: Approval policies

- Always ask.
- Approve once for the current operation.
- Approve for a short, visible time window.
- Allow one client, secret, consumer and destination combination.
- Require fresh Touch ID for higher-risk destinations.
- Show the blast radius before approving a multi-destination request.
- Expire every standing permission automatically.

Policies will never allow arbitrary paths, commands or destinations.

## 1.5: Reliability, security and iPhone approval

Available early:

- Local request and completion notifications.
- Optional Telegram approvals paired to one private chat and user with
  expiring, single-use callbacks and no secret values.

Telegram Bot API metadata is not end-to-end encrypted. The iPhone companion
below is now implemented in source as the stronger remote approval path. A
physical-device CloudKit and push canary remains required before release.

- Pair clients using dedicated keys or verified code-signing identity.
- Add tamper-evident, content-free audit history.
- Fuzz request and package parsers and test protocol compatibility.
- Recover queues safely after crashes.
- Audit destination ownership and permissions.
- Ship a signed, notarised installer with verified updates and rollback.
- Export security configuration and receipts without credentials.
- Add the native iPhone approval companion described below.

### Native iPhone companion

Available in the current source build:

1. Pair one iPhone and Mac using device public keys, Mac owner authentication
   and a matching verification code.
2. Carry friendly, content-free request metadata through the owner's private
   CloudKit database.
3. Show friendly secret, consumer and destination names, the reason, expiry and
   blast radius on the phone.
4. Use Face ID to sign a single-use approval bound to the request ID and expiry.
5. Verify the signature on the Mac, then read and deliver the secret locally.
6. Accept API keys and passwords on the phone, encrypt them to the verified Mac
   key and import them into the Mac's device-only Keychain while the app is
   open and unlocked.
7. Add or replace a credential with one protected value field by default, or
   the bounded username-and-password format when selected.
8. Automatically show the same compact prompt on the Mac when an AI client
   requests a credential that is not saved yet.

The iPhone is not a second long-term vault. The relay never receives a
plaintext credential value. Requests expire, decisions cannot be replayed and
the workflow fails closed if either device cannot verify the other.

Still required before release:

- create and promote the production CloudKit schema
- sign both targets with the required iCloud and notification entitlements
- pass a two-device pairing-code canary
- verify foreground, background and terminated-state notification delivery
- pass one dummy approval, denial, encrypted credential import and replay test

## 1.6: Direct provider integrations

After cross-device delivery and lifecycle controls are proven, add allowlisted
adapters for:

- n8n credentials
- GitHub Actions secrets
- Cloudflare tokens
- Vercel environment variables
- SSH keys and certificates
- database credentials
- application-specific API keys
- supported short-lived credential providers

Provider adapters install or rotate credentials directly. They never return
plaintext to the requesting model.

## Fixed security rules

- No secret values in model context, chat, command arguments, logs or receipts.
- No request-supplied paths, commands, hosts or provider operations.
- Owner-created allowlists define every permitted destination and consumer.
- Requests expire, reject replay and fail closed.
- Dummy canaries prove the exact consumer path before production use.

Detailed release contracts live in
[the capability map](docs/CAPABILITY-MAP-1.1-1.6.md) and
[the 1.1 to 1.6 specification](docs/SPEC-1.1-1.6.md).
