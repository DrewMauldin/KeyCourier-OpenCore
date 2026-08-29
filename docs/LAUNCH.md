# KeyCourier production launch and rollback

## Launch criteria

- The full core test bundle passes.
- The Release app and CLI build without warnings.
- The Mac artifact has a Developer ID signature, hardened runtime, inspected production entitlements, a successful notarisation result and a stapled ticket.
- The iPhone artifact has an Apple Distribution signature, production CloudKit/APNs entitlements, the privacy manifest and a processed App Store Connect build.
- Every distributed artifact has a matching redacted `RELEASE-MANIFEST.json` binding its source commit/tree, toolchain, target/build and SHA-256 to its signing and notarisation evidence.
- A disposable request can be submitted, displayed and denied without secret material entering its receipt.
- A disposable secret can be stored in the data-protection Keychain.
- The local consumer flow passes the user-presence-controlled Keychain read and writes only after approval.
- Support directories and persisted request metadata remain owner-only.
- Source history contains no credential or private-key material.
- The privacy and support routes return their intended pages over valid TLS.
- A physical Mac and iPhone pass pairing, approve, deny, notification and encrypted credential-import canaries with dummy values.
- App Store privacy, export-compliance, pricing and review metadata have owner approval.

Remote Mac Mini and VPS delivery remains fail-closed until each separate host-agent rollout and dummy canary is complete.

## Rollback

1. Quit KeyCourier.
2. Inspect the timestamped copies under `~/Library/Application Support/KeyCourier/Install Backups`.
3. Move `/Applications/KeyCourier.app` aside and restore the selected app backup to that path.
4. Restore a matching agent-skill backup if the request contract changed.
5. Launch KeyCourier and submit a dummy request.

An app rollback does not remove or rewrite Keychain vault entries. Destination files retain their own `.keycourier.previous` copy for one-step content rollback.

## Release boundary

Repository verification proves source and unsigned builds only. Developer ID notarisation, Apple Distribution, production CloudKit, physical-device behaviour, website publication and App Review are separate evidence gates. The release scripts never upload unless the owner explicitly requests notarisation with `--notarize`; the iPhone workflow exports locally and never uploads.
