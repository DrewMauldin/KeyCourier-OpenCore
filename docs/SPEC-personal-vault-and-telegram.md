# Specification: personal vault and Telegram approvals

## Objective

Make KeyCourier easier to use as one owner's daily credential vault while
preserving the fixed-consumer rule. Normal screens use friendly names. Secret,
consumer and target identifiers appear only inside Advanced disclosures.

## Selected architecture

### Caller view

1. Add a credential or explicitly import an owner-selected `.env` file.
2. Organise it by project, environment and owner, then set rotation or expiry
   dates where useful.
3. Optionally enable Telegram approval for that exact credential by re-entering
   its value.
4. Let an AI client submit the existing identifier-only request contract.
5. Approve in the Mac app or through the paired Telegram button. The client
   receives only the existing content-free receipt.

### Shape

- `SecretMetadata` is the single source of truth for friendly organisation,
  lifecycle dates and per-secret Telegram eligibility. New fields decode with
  safe defaults so existing metadata remains valid.
- `DotenvSecretImporter` parses a bounded owner-selected file in memory. The app
  persists values to Keychain and does not retain the source path or contents.
- `SecretBackupBundle` validates the complete credential set before it is
  encrypted to one or more public age recipients. Output files are atomic and
  mode 600. A new recipient list plus a fresh export is the rekey operation.
- `FileTelegramApprovalStore` persists only pairing metadata, opaque request
  UUIDs, random nonces, expiry, bounded send attempts and consumed state.
- `TelegramBotTokenStore` keeps the bot token in a separate device-only
  Keychain item. It never enters metadata, logs or request files.
- `TelegramBotAPI` talks only to the fixed HTTPS Telegram Bot API host. Pairing
  binds one private chat and Telegram user using a one-time 48-bit code.
- Callback data contains an action and random nonce only. The app validates the
  chat, user, nonce, request state and expiry before approving or declining.

## Alternative considered

A separate approval daemon or hosted broker could poll Telegram independently
of the app. It was rejected because it introduces another long-running process,
deployment path and network trust boundary. The native app already owns the
request queue and secret operation, so embedding the bounded adapter has the
deeper and smaller interface.

Separate lifecycle records joined to credentials were also considered. They
were rejected because both files would have the same owner and update path,
creating synchronisation and orphan risks without an independent lifecycle.

## Security boundaries

- Default credentials retain Keychain user-presence access control.
- Telegram is explicitly enabled per credential and requires the value to be
  entered again. That item moves to a separate
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` service used by the signed app.
- Local approval for Telegram-capable items performs macOS owner
  authentication before release.
- Telegram approval relies on possession of the paired Telegram account and
  bot conversation plus the single-use request token. A consumed or expired
  token fails closed.
- Telegram Bot API messages are not end-to-end encrypted. Messages contain
  friendly metadata but no credential values or routing identifiers.
- The requesting model never receives a credential value, Telegram token,
  recipient, recovery identity or decrypted backup.

## Verification

- Backwards-compatible metadata decoding and lifecycle status tests
- Bounded `.env` parser and encrypted backup round-trip tests
- Telegram pairing-state, chat/user binding, replay and content-free state tests
- Existing request, receipt, Keychain, dotenv and remote-age regression suite
- Unsigned Debug build, signed Release installer and runtime launch check
