---
name: keycourier
description: Request owner-approved installation of an existing credential through the local KeyCourier macOS app. Use when a task needs a secret in an allowlisted consumer but the agent must not receive plaintext.
---

# KeyCourier

Use KeyCourier as a one-way approval broker. For the built-in This Mac, Mac Mini and VPS destinations, the agent only needs the simple destination name, reason, request ID and content-free receipt. It must never ask for, accept, read, print, log or transmit the credential value itself.

## Request delivery

1. For This Mac, Mac Mini or VPS, use the matching built-in destination name. For any custom destination, obtain the owner-approved `secret-id`, `target` and `consumer` identifiers.
2. Submit exactly one content-free request:

```sh
keycourier request --client codex --destination this-mac \
  --reason "Plain-language reason for this installation"
```

Use `--destination this-mac` for the current computer, `mac-mini` for Mac Mini or `vps` for VPS. Use `claude` or `opencode` for the client value when applicable. The command opens KeyCourier and prints a JSON request ID.

For a custom destination only, use the compatible explicit form:

```sh
keycourier request --client codex --secret-id SECRET_ID \
  --target TARGET_ID --consumer CONSUMER_ID \
  --reason "Plain-language reason for this installation"
```

3. After the owner responds, check the receipt with `keycourier status REQUEST_ID`.
4. Treat only `status: verified` with `code: consumerVerified` as delivery success. Report denied, failed, offline or not-configured receipts without attempting a bypass.

## Boundaries

- Do not add a plaintext flag, pipe a value through stdin, inspect KeyCourier's private files or query the Keychain directly.
- Do not substitute `.env`, shell history, chat, logs, clipboard or repository files when KeyCourier is unavailable.
- Do not infer permission for a different consumer or target. Submit a new request when the destination changes.
- Verify the real consumer without displaying its environment or credential value.
