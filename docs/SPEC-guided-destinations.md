# Spec: Guided destinations

## Objective

Make the common KeyCourier flow understandable without exposing its internal routing vocabulary. An owner can save any number of independent credentials and approve delivery to This Mac, Mac Mini, VPS or Cloud Memory Projection Executor. Agents select a saved credential from KeyCourier's content-free metadata and request an approved destination.

## Built-in contract

| Destination | Legacy shortcut secret ID | Consumer ID | Target ID |
|---|---|---|---|
| This Mac | `this-mac-secret` | `this-mac` | `this-mac` |
| Mac Mini | `mac-mini-secret` | `mac-mini` | `mac-mini` |
| VPS | `vps-secret` | `vps` | `vps` |
| Cloud Memory Projection Executor | `cloud-memory-projection-secret` | `cloud-memory-projection` | `vps` |

These identifiers are stable compatibility interfaces for agents and receipts. They appear only in Advanced technical details and documentation, not in the primary setup flow.

## Primary experience

- Home shows a credential count with prominent Add credential and Manage credentials actions.
- Add credential always creates a separate credential with a unique ID. Users can save as many app passwords, API keys and logins as they need.
- Home also shows four destination rows in this order: This Mac, Mac Mini, VPS and Cloud Memory Projection Executor.
- Each destination row says whether it is ready to receive approved requests. Home does not ask for a default or shortcut credential.
- Any saved credential can be delivered to any approved destination when explicitly requested; credentials are not owned by one destination.
- Requests and activity use the friendly destination name when their identifiers match a built-in destination.
- Custom secrets and destinations remain available under Advanced for backward compatibility.

## Registration and safety

- KeyCourier registers all four built-in consumer profiles when they are missing.
- This Mac is a local consumer that writes only to KeyCourier's private managed dotenv file. It never appears in remote connection testing.
- Registration is idempotent and never overwrites an existing profile with the same ID.
- A profile collision is shown as needing attention rather than silently repaired.
- Registration does not mean remote delivery is configured. Mac Mini, VPS and Cloud Memory Projection Executor remain fail-closed until each target has its own reviewed age recipient, allowlisted helper, replay store and dummy-secret canary.
- Secret values remain only in the data-protection Keychain and short-lived form memory. They never enter metadata, requests, receipts, logs or agent arguments.

## Agent experience

An agent first lists content-free credential metadata with `keycourier secrets`, then requests the selected credential using its exact ID and the registered destination routing IDs:

```sh
keycourier request --client codex --secret-id credential-… --target this-mac --consumer this-mac --reason "Install the saved credential locally"
```

The destination-only shortcut remains available for legacy fixed credentials. New credentials use the explicit `--secret-id`, `--target` and `--consumer` form so choosing a destination never silently substitutes a different credential.

## Acceptance criteria

- Exactly four built-in destinations have stable, tested mappings.
- Missing built-in consumers are registered once without changing unrelated or colliding profiles.
- Agent credential listing and requests expose content-free metadata and identifiers only, never secret material.
- The main UI contains no Secret ID, Consumer ID, Target ID, consumer or remote profile terminology.
- Requests, history and destination status use plain language and remain accessible by keyboard and VoiceOver.
- Core tests pass, the native app builds, and the launched signed app is visually checked with dummy or empty data only.
