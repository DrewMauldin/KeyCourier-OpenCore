import CryptoKit
import Foundation
import KeyCourierCore

private let storeBundleIdentifier = "com.drewsdigest.KeyCourier"
private let prohibitedOptions: Set<String> = [
    "--value",
    "--password",
    "--token",
    "--secret",
    "--secret-value",
    "--private-key"
]
private let requestOptions: Set<String> = [
    "--client",
    "--secret-id",
    "--target",
    "--consumer",
    "--reason"
]
private let configureOptions: Set<String> = [
    "--consumer",
    "--name",
    "--target",
    "--path",
    "--variable"
]
private let configureLoginOptions: Set<String> = [
    "--consumer",
    "--name",
    "--target",
    "--path",
    "--username-variable",
    "--password-variable"
]

private func printJSON(_ fields: [String: String]) {
    guard let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) else {
        return
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("keycourier-bridge: \(message)\n".utf8))
    exit(64)
}

private func failJSON(_ error: Error) -> Never {
    let response: [String: String]
    let exitCode: Int32
    switch error {
    case BridgeProtocolError.queueLimitExceeded:
        response = ["code": "queueFull", "status": "failed"]
        exitCode = 75
    case BridgeProtocolError.expired:
        response = ["code": "expired", "status": "failed"]
        exitCode = 65
    case BridgeProtocolError.replayedRecord,
         BridgeProtocolError.conflictingRecord,
         BridgeProtocolError.claimExists:
        response = ["code": "conflict", "status": "failed"]
        exitCode = 75
    case is BridgeProtocolError, is KeyCourierError:
        response = ["code": "invalidRequest", "status": "failed"]
        exitCode = 65
    case is BridgeStorageError:
        response = ["code": "notConfigured", "status": "notConfigured"]
        exitCode = 78
    default:
        response = ["code": "unavailable", "status": "failed"]
        exitCode = 70
    }
    printJSON(response)
    exit(exitCode)
}

private func optionName(_ value: String) -> String {
    String(value.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
}

private func loadQueue() throws -> BridgeQueue {
    BridgeQueue(root: try BridgeSharedContainer.root())
}

private func bridgeMetadataStore() -> FileMetadataStore {
    let root = FileManager.default.homeDirectoryForCurrentUser
        .appending(path: "Library/Application Support/KeyCourierBridge/Metadata", directoryHint: .isDirectory)
    return FileMetadataStore(root: root)
}

private func publicKeys(for identity: BridgeIdentity) throws -> (signing: Data, agreement: Data) {
    let signing = try Curve25519.Signing.PrivateKey(
        rawRepresentation: identity.keys.signingPrivateKey
    ).publicKey.rawRepresentation
    let agreement = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: identity.keys.keyAgreementPrivateKey
    ).publicKey.rawRepresentation
    return (signing, agreement)
}

private func ensureRegistration(
    queue: BridgeQueue,
    identity: BridgeIdentity
) throws -> BridgeRegistration {
    let keys = try publicKeys(for: identity)
    if let existing = try queue.registrations().first(where: { $0.bridgeID == identity.id }) {
        guard existing.signingPublicKey == keys.signing,
              existing.keyAgreementPublicKey == keys.agreement else {
            throw BridgeStorageError.invalidIdentity
        }
        try BridgeCrypto.verify(existing)
        return existing
    }

    // An expired or malformed record for this identity cannot be reused.
    try? queue.removeRegistration(for: identity.id)
    let registration = try BridgeCrypto.registration(
        bridgeID: identity.id,
        displayName: "KeyCourier Bridge",
        keys: identity.keys
    )
    let signed = try BridgeCrypto.sign(
        registration,
        privateKey: identity.keys.signingPrivateKey
    )
    _ = try queue.save(signed)
    return signed
}

private func trustedPairing(
    queue: BridgeQueue,
    registration: BridgeRegistration,
    peerStore: BridgePinnedPeerStore
) throws -> BridgePairingProposal {
    guard let proposal = try queue.proposal(for: registration.bridgeID) else {
        throw BridgeStorageError.invalidIdentity
    }
    try BridgeCrypto.verify(proposal)
    guard proposal.bridgeID == registration.bridgeID,
          proposal.registrationDigest == (try registration.digest()) else {
        throw BridgeProtocolError.invalidRecord
    }
    guard let grant = try queue.grant(for: registration.bridgeID) else {
        throw BridgeStorageError.invalidIdentity
    }
    try BridgeCrypto.verify(
        grant,
        appSigningPublicKey: proposal.appSigningPublicKey
    )
    guard grant.bridgeID == registration.bridgeID,
          grant.registrationDigest == (try registration.digest()),
          grant.proposalDigest == (try proposal.digest()) else {
        throw BridgeProtocolError.invalidRecord
    }
    let registrationDigest = try registration.digest()
    if let revocation = try queue.revocation(for: registration.bridgeID) {
        try BridgeCrypto.verify(
            revocation,
            signingPublicKey: proposal.appSigningPublicKey,
            expectedBridgeID: registration.bridgeID
        )
        guard revocation.registrationDigest != registrationDigest else {
            throw BridgeStorageError.trustRevoked
        }
    }

    let expectedPeer = try BridgePinnedPeer(
        bridgeID: registration.bridgeID,
        signingPublicKey: proposal.appSigningPublicKey,
        registrationDigest: registrationDigest
    )
    if let pinnedPeer = try peerStore.load() {
        guard pinnedPeer == expectedPeer else { throw BridgeStorageError.invalidIdentity }
    } else {
        try peerStore.save(expectedPeer)
    }
    if try queue.revocation(for: registration.bridgeID) != nil {
        try queue.removeRevocation(for: registration.bridgeID)
    }
    return proposal
}

private func requirePersistedTrust(
    identity: BridgeIdentity,
    peerStore: BridgePinnedPeerStore,
    queue: BridgeQueue
) throws -> BridgePinnedPeer {
    guard let peer = try peerStore.load(), peer.bridgeID == identity.id else {
        throw BridgeStorageError.invalidIdentity
    }
    guard (try? Curve25519.Signing.PublicKey(rawRepresentation: peer.signingPublicKey)) != nil,
          peer.keyAgreementPublicKey == nil,
          peer.registrationDigest.count == 32 else {
        throw BridgeStorageError.invalidIdentity
    }

    if let revocation = try queue.revocation(for: peer.bridgeID) {
        try BridgeCrypto.verify(
            revocation,
            signingPublicKey: peer.signingPublicKey,
            expectedBridgeID: peer.bridgeID
        )
        if revocation.registrationDigest == peer.registrationDigest {
            try peerStore.delete()
            try queue.removeRevocation(for: peer.bridgeID)
            throw BridgeStorageError.trustRevoked
        }
        // A valid tombstone for an older registration cannot revoke the
        // newly pinned peer. Remove it only after authenticating its signer.
        try queue.removeRevocation(for: peer.bridgeID)
    }
    return peer
}

private func makeRequest(from values: [String: String]) throws -> SecretRequest {
    guard let clientValue = values["--client"],
          let client = AgentClient(rawValue: clientValue),
          let secretValue = values["--secret-id"],
          let targetValue = values["--target"],
          let consumerValue = values["--consumer"],
          let reason = values["--reason"],
          let secretID = try? SecretID(validating: secretValue),
          let targetID = try? TargetID(validating: targetValue),
          let consumerID = try? ConsumerID(validating: consumerValue) else {
        throw BridgeProtocolError.invalidRecord
    }
    return try SecretRequest(
        client: client,
        secretID: secretID,
        targetID: targetID,
        consumerID: consumerID,
        reason: reason
    )
}

private func wakeStoreApp() {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    process.arguments = ["-b", storeBundleIdentifier]
    try? process.run()
}

private func processPendingCommands() async throws -> (processed: Int, unresolved: Int) {
    let identity = try BridgeKeychainIdentityStore(role: .bridge).loadOrCreate()
    let queue = try loadQueue()
    let pinnedStore = try requirePersistedTrust(
        identity: identity,
        peerStore: BridgePinnedPeerStore(role: .bridge),
        queue: queue
    )
    let metadata = bridgeMetadataStore()
    let processor = BridgeCommandProcessor(
        queue: queue,
        identity: identity,
        pinnedStore: pinnedStore,
        profile: { consumerID in
            try metadata.consumers().first { $0.id == consumerID }
        },
        install: { secret, profile in
            switch profile.destination {
            case .dotenv:
                _ = try DotenvInstaller().install(secret, for: profile)
            case .dotenvLogin:
                let login = try CompanionCredentialMaterial.usernamePassword(
                    fromDeliveryData: secret
                )
                _ = try DotenvInstaller().install(
                    username: login.username,
                    password: login.password,
                    for: profile
                )
            case .remoteAge:
                throw KeyCourierError.unsupportedDestination
            }
        }
    )
    var processed = 0
    var unresolved = 0
    for command in try queue.pendingCommands().reversed() {
        do {
            _ = try await processor.process(command)
            processed += 1
        } catch {
            unresolved += 1
        }
    }
    return (processed, unresolved)
}

private func run() async {
    let arguments = Array(CommandLine.arguments.dropFirst())
    let command = arguments.first ?? "process"

    switch command {
case "pair":
    guard arguments.count == 1 else { fail("pair does not accept options") }
    do {
        let identityStore = BridgeKeychainIdentityStore(role: .bridge)
        let identity = try identityStore.loadOrCreate()
        let queue = try loadQueue()
        let peerStore = BridgePinnedPeerStore(role: .bridge)
        if (try? requirePersistedTrust(
            identity: identity,
            peerStore: peerStore,
            queue: queue
        )) != nil {
            printJSON([
                "bridgeID": identity.id.uuidString.lowercased(),
                "status": "paired"
            ])
            exit(0)
        }
        let registration = try ensureRegistration(queue: queue, identity: identity)
        if let proposal = try? queue.proposal(for: registration.bridgeID),
           (try? BridgeCrypto.verify(proposal)) != nil,
           proposal.registrationDigest == (try? registration.digest()) {
            let code = try BridgeCrypto.pairingCode(
                registration: registration,
                proposal: proposal
            )
            if let grant = try? queue.grant(for: registration.bridgeID),
               (try? BridgeCrypto.verify(
                   grant,
                   appSigningPublicKey: proposal.appSigningPublicKey
               )) != nil,
               grant.registrationDigest == (try? registration.digest()),
               grant.proposalDigest == (try? proposal.digest()) {
                try await LocalOwnerPresenceAuthorizer().authorize(
                    reason: "Confirm KeyCourier pairing code \(code)"
                )
                _ = try trustedPairing(
                    queue: queue,
                    registration: registration,
                    peerStore: peerStore
                )
                printJSON([
                    "bridgeID": registration.bridgeID.uuidString.lowercased(),
                    "pairingCode": code,
                    "status": "paired"
                ])
            } else {
                printJSON([
                    "bridgeID": registration.bridgeID.uuidString.lowercased(),
                    "pairingCode": code,
                    "status": "waitingForOwner"
                ])
            }
        } else {
            printJSON([
                "bridgeID": registration.bridgeID.uuidString.lowercased(),
                "status": "waitingForStore"
            ])
        }
    } catch {
        failJSON(error)
    }

case "request":
    let options = Array(arguments.dropFirst())
    guard options.count.isMultiple(of: 2) else {
        fail("request options must be supplied as flag/value pairs")
    }
    var values: [String: String] = [:]
    for index in stride(from: 0, to: options.count, by: 2) {
        let option = options[index]
        let name = optionName(option)
        guard option == name, requestOptions.contains(name), !prohibitedOptions.contains(name) else {
            fail("unsupported request option")
        }
        guard values[name] == nil, !options[index + 1].isEmpty else {
            fail("invalid request option")
        }
        values[name] = options[index + 1]
    }
    guard values.count == requestOptions.count else {
        fail("request requires client, secret, target, consumer and reason")
    }
    do {
        let request = try makeRequest(from: values)
        let identityStore = BridgeKeychainIdentityStore(role: .bridge)
        let identity = try identityStore.loadOrCreate()
        let queue = try loadQueue()
        _ = try requirePersistedTrust(
            identity: identity,
            peerStore: BridgePinnedPeerStore(role: .bridge),
            queue: queue
        )
        guard let profile = try bridgeMetadataStore().consumers().first(where: {
            $0.id == request.consumerID
        }), profile.targetID == request.targetID else {
            throw BridgeStorageError.invalidIdentity
        }
        let signedRequest = try BridgeCrypto.sign(
            SignedBridgeRequest(
                bridgeID: identity.id,
                request: request,
                requestNonce: BridgeCrypto.randomNonce()
            ),
            privateKey: identity.keys.signingPrivateKey
        )
        _ = try queue.enqueue(signedRequest)
        wakeStoreApp()
        printJSON([
            "requestID": request.id.uuidString.lowercased(),
            "status": "pending"
        ])
    } catch {
        failJSON(error)
    }

case "configure":
    let options = Array(arguments.dropFirst())
    guard options.count.isMultiple(of: 2) else {
        fail("configure options must be supplied as flag/value pairs")
    }
    var values: [String: String] = [:]
    for index in stride(from: 0, to: options.count, by: 2) {
        let option = options[index]
        let name = optionName(option)
        guard option == name,
              configureOptions.contains(name),
              !prohibitedOptions.contains(name),
              values[name] == nil,
              !options[index + 1].isEmpty else {
            fail("invalid configure option")
        }
        values[name] = options[index + 1]
    }
    guard values.count == configureOptions.count,
          let consumerValue = values["--consumer"],
          let targetValue = values["--target"],
          let displayName = values["--name"],
          let path = values["--path"],
          let variable = values["--variable"] else {
        fail("configure requires consumer, name, target, path and variable")
    }
    do {
        let identity = try BridgeKeychainIdentityStore(role: .bridge).loadOrCreate()
        _ = try requirePersistedTrust(
            identity: identity,
            peerStore: BridgePinnedPeerStore(role: .bridge),
            queue: try loadQueue()
        )
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: consumerValue),
            displayName: displayName,
            targetID: TargetID(validating: targetValue),
            destination: .dotenv(path: path, variable: variable)
        )
        try await LocalOwnerPresenceAuthorizer().authorize(
            reason: "Configure a KeyCourier destination for \(profile.displayName)"
        )
        try bridgeMetadataStore().save(profile)
        printJSON([
            "consumer": profile.id.rawValue,
            "status": "configured",
            "target": profile.targetID.rawValue
        ])
    } catch {
        failJSON(error)
    }

case "configure-login":
    let options = Array(arguments.dropFirst())
    guard options.count.isMultiple(of: 2) else {
        fail("configure-login options must be supplied as flag/value pairs")
    }
    var values: [String: String] = [:]
    for index in stride(from: 0, to: options.count, by: 2) {
        let option = options[index]
        let name = optionName(option)
        guard option == name,
              configureLoginOptions.contains(name),
              !prohibitedOptions.contains(name),
              values[name] == nil,
              !options[index + 1].isEmpty else {
            fail("invalid configure-login option")
        }
        values[name] = options[index + 1]
    }
    guard values.count == configureLoginOptions.count,
          let consumerValue = values["--consumer"],
          let targetValue = values["--target"],
          let displayName = values["--name"],
          let path = values["--path"],
          let usernameVariable = values["--username-variable"],
          let passwordVariable = values["--password-variable"] else {
        fail("configure-login requires consumer, name, target, path and both variables")
    }
    do {
        let identity = try BridgeKeychainIdentityStore(role: .bridge).loadOrCreate()
        _ = try requirePersistedTrust(
            identity: identity,
            peerStore: BridgePinnedPeerStore(role: .bridge),
            queue: try loadQueue()
        )
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: consumerValue),
            displayName: displayName,
            targetID: TargetID(validating: targetValue),
            destination: .dotenvLogin(
                path: path,
                usernameVariable: usernameVariable,
                passwordVariable: passwordVariable
            )
        )
        try await LocalOwnerPresenceAuthorizer().authorize(
            reason: "Configure a KeyCourier login destination for \(profile.displayName)"
        )
        try bridgeMetadataStore().save(profile)
        printJSON([
            "consumer": profile.id.rawValue,
            "status": "configured",
            "target": profile.targetID.rawValue
        ])
    } catch {
        failJSON(error)
    }

case "process":
    guard arguments.isEmpty || arguments.count == 1 else {
        fail("process does not accept options")
    }
    do {
        let result = try await processPendingCommands()
        printJSON([
            "processed": String(result.processed),
            "status": result.unresolved == 0 ? "ready" : "attention",
            "unresolved": String(result.unresolved)
        ])
    } catch {
        failJSON(error)
    }

case "reset":
    guard arguments.count == 1 else { fail("reset does not accept options") }
    do {
        try await LocalOwnerPresenceAuthorizer().authorize(reason: "Reset KeyCourier Bridge pairing")
        let queue = try loadQueue()
        try queue.purgeAll()
        try BridgePinnedPeerStore(role: .bridge).delete()
        printJSON(["status": "unpaired"])
    } catch {
        failJSON(error)
    }

case "status":
    guard arguments.count == 2, let requestID = UUID(uuidString: arguments[1]) else {
        fail("status requires a request UUID")
    }
    do {
        let identityStore = BridgeKeychainIdentityStore(role: .bridge)
        let identity = try identityStore.loadOrCreate()
        let queue = try loadQueue()
        _ = try requirePersistedTrust(
            identity: identity,
            peerStore: BridgePinnedPeerStore(role: .bridge),
            queue: queue
        )
        let keys = try publicKeys(for: identity)
        if let receipt = try queue.receipt(forRequestID: requestID) {
            try BridgeCrypto.verify(
                receipt,
                signingPublicKey: keys.signing,
                expectedBridgeID: identity.id,
                expectedRequestID: requestID
            )
            printJSON([
                "code": receipt.receipt.code.rawValue,
                "requestID": requestID.uuidString.lowercased(),
                "status": receipt.receipt.status.rawValue
            ])
        } else if let request = try queue.request(for: requestID) {
            try BridgeCrypto.verify(
                request,
                signingPublicKey: keys.signing,
                expectedBridgeID: identity.id
            )
            printJSON([
                "requestID": requestID.uuidString.lowercased(),
                "status": "pending"
            ])
        } else {
            printJSON([
                "code": "unknown",
                "requestID": requestID.uuidString.lowercased(),
                "status": "unknown"
            ])
        }
    } catch {
        failJSON(error)
    }

default:
    fail("use pair, configure, configure-login, request, process, reset or status REQUEST_ID")
    }
}

Task {
    await run()
    exit(0)
}
dispatchMain()
