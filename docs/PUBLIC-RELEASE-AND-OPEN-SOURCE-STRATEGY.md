# KeyCourier Public Release and Open Source Strategy

Last verified: 29 August 2026

## Recommendation

KeyCourier is prepared as two complementary App Store products:

- KeyCourier for Mac is a USD $9.99 one-time purchase;
- the KeyCourier iPhone companion is free;
- the complete client-side security boundary published under MPL-2.0;
- revenue from the official signed, notarised and App Store builds, update delivery and support;
- no subscription until KeyCourier operates a material recurring service.

This is closer to commercial open source than a conventional open-core split. For a credential product, closing any code that can see plaintext or authorise delivery would weaken the trust argument.

## Product split

The sandboxed Mac App Store edition:

- stores credentials in Keychain;
- uses CloudKit and normal network APIs for pairing and approvals;
- writes only to app-private locations or files explicitly selected through Apple's document picker and security-scoped access;
- does not install a CLI, host agent or other executable;
- does not depend on launching `/usr/bin/ssh` or a separately installed `age` binary.

The separately distributed Developer ID edition supports advanced local automation, CLI installation, SSH delivery and host-agent workflows. Apple supports Developer ID signing and notarisation for Mac software distributed outside the Mac App Store.

Do not present the editions as identical. Call the limits out clearly, for example “App Store edition” and “Automation edition”.

The Mac and iPhone apps intentionally use separate App Store Connect records because pricing is record-wide. Both production-signed targets use the same intended CloudKit container, while the free iPhone app remains useful only with the paid Mac product.

## Pricing model

This is a pricing model, not a revenue forecast.

### Current price

| Product | Base price | Purpose |
| --- | ---: | --- |
| KeyCourier for Mac | USD $9.99 one time | Simple paid desktop product |
| KeyCourier iPhone companion | Free | Pairing, approvals and encrypted credential entry for Mac owners |

Revisit pricing only after real adoption and support evidence. Do not add a launch discount, subscription or second iPhone charge to the first release.

Apple currently offers hundreds of price points and automatically calculates equivalent storefront prices from a chosen base country. If eligible and enrolled in the App Store Small Business Program, commission on paid apps and in-app purchases is 15% up to the programme threshold.

### Why not a subscription

The current value is local software, device pairing and owner approval. A subscription would be hard to justify without an ongoing paid service such as managed team policy, hosted infrastructure or active security monitoring. It would also cut against the simple, local-first positioning.

### Paid upfront

The Mac app is paid upfront. This avoids an entitlement screen, account system and artificial feature gates. The iPhone companion is free and does not contain an in-app purchase.

## Open source trust model

### Publish the entire security boundary

At minimum, publish every component that:

- reads, stores, encrypts, decrypts or deletes credential material;
- decides whether a request is authorised;
- defines the request, approval, receipt and replay-protection protocol;
- talks to Keychain or CloudKit;
- writes credentials to a destination;
- installs or runs the CLI and host agent;
- enforces allowlists, expiry and content-free receipts.

The LLM must continue to receive only operation status and content-free receipts, never plaintext credentials.

### Deterministic public mirror boundary

The public repository must be a fresh export, not a visibility change on this
working repository. Run `scripts/export-open-core.sh` from a clean, committed
checkout and give it a new directory outside the checkout. The exporter reads
only the selected commit with `git archive`, so uncommitted files and Git
history cannot enter the mirror. It writes an `OPEN_CORE_MANIFEST.json` that
records the source commit and tree plus a SHA-256 and mode for every exported
file. All manifest paths are relative.

The allowlist contains the KeyCourier app, iPhone companion, Store app, Bridge,
CLI, Core library, generic host-agent receiver and tests; the Xcode project,
entitlements, integrations, release configuration and verification scripts;
and the licence, security, contribution, trademark, third-party and protocol
documentation. Public product identifiers such as bundle IDs, the Apple team
ID and the CloudKit container remain unchanged as attribution and build
configuration; they are not credentials and are not parameterised.

The export fails closed for the private Cloud Memory projection runner and its
test, host-deployment scripts, the raw remote-delivery deployment plan, App
Store metadata, task notes, ignored release artifacts and `.git`. The linked
remote-delivery page is replaced in the export by a protocol-only document
that contains no hostnames, addresses, users or deployment paths. Any future
allowlist addition requires an explicit review in the exporter.

### Licence

MPL-2.0 is the best initial fit. Its file-level copyleft requires changes to MPL-covered files to remain available while allowing KeyCourier to be combined with proprietary packaging or future commercial modules. It is a better trust signal than a source-available licence and less restrictive than GPL-style whole-program copyleft.

Before publishing, obtain legal review of the licence, App Store terms and any third-party dependencies. Add:

- `LICENSE` with the MPL-2.0 text;
- `THIRD_PARTY_NOTICES.md` for third-party attribution;
- `CONTRIBUTING.md`;
- `SECURITY.md` with private vulnerability reporting;
- a trademark policy reserving the KeyCourier name and official icons;
- a public threat model and data-flow diagram;
- dependency lock files and a software bill of materials for each release;
- signed Git tags and source archives corresponding to every official binary;
- reproducible-build instructions, or a precise explanation of unavoidable Apple-signing differences.

### What remains commercial

Charge for the official KeyCourier builds and the assurance around them:

- Apple-reviewed App Store delivery;
- Developer ID signing and notarisation for the automation edition;
- controlled updates;
- tested compatibility releases;
- support and security response;
- the KeyCourier trademark and official distribution channels.

Do not make the crypto or credential-handling code the closed “premium” part. That is exactly the code security-conscious buyers need to inspect.

## Public launch gates

Do not call the product production-ready until all of these are independently verified:

- Mac crash regression is closed with a distribution build, not only a Debug build.
- All core tests, Mac build and iPhone build pass from a clean checkout.
- A physical-device test proves pairing, foreground/background/terminated notifications, approve, deny, encrypted import, expiry and replay rejection.
- Production CloudKit schema is promoted and both signed apps use the same intended container.
- Both App Store Connect records, bundle IDs, pricing and their shared CloudKit boundary are confirmed before either platform is approved.
- The Mac App Store edition passes a sandbox capability audit.
- The Developer ID edition passes hardened-runtime, signing, notarisation and Gatekeeper checks.
- Privacy policy, App Privacy answers and support pages are live and accurate.
- Export compliance has been answered for the app's use of encryption before TestFlight or App Review.
- An independent security reviewer has inspected the protocol and credential-handling paths.
- Recovery is documented for a lost iPhone, lost Mac, revoked pairing and failed CloudKit account.

## Suggested sequence

1. Publish the security design and licence before taking payment.
2. Stabilise the current Developer ID Mac build and physical-device companion flow.
3. Decide whether the Mac App Store edition can retain enough value after sandboxing.
4. Inspect both App Store Connect records and their shared CloudKit boundary before public submission.
5. Run a small TestFlight and notarised Mac beta with dummy credentials only.
6. Commission an independent security review and resolve material findings.
7. Launch the Mac app at USD $9.99 and keep the iPhone companion free.

## Sources

- [Apple App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- [Apple: Add platforms and create a universal purchase](https://developer.apple.com/help/app-store-connect/create-an-app-record/add-platforms)
- [Apple: Set a price](https://developer.apple.com/help/app-store-connect/manage-app-pricing/set-a-price)
- [Apple: In-app purchase types](https://developer.apple.com/help/app-store-connect/configure-in-app-purchase-settings/overview-for-configuring-in-app-purchases)
- [Apple App Store Small Business Program](https://developer.apple.com/app-store/small-business-program/)
- [Apple Developer ID distribution](https://developer.apple.com/support/developer-id/)
- [Apple: App privacy details](https://developer.apple.com/app-store/app-privacy-details/)
- [Apple: Export compliance overview](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance/)
- [Mozilla Public License 2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
- [Secrets Australian App Store listing](https://apps.apple.com/au/app/secrets-password-manager/id1591056366)
- [Strongbox Australian App Store listing](https://apps.apple.com/au/app/strongbox-password-manager/id897283731)
