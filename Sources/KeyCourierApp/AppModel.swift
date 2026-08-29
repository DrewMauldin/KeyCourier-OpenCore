import Foundation
import KeyCourierCore
import Observation

enum RemoteConnectionState: Equatable {
    case notTested
    case checking
    case connected
    case needsAttention
}

@MainActor
@Observable
final class AppModel {
    var selection: SidebarSection = .home
    private(set) var secrets: [SecretMetadata] = []
    private(set) var consumers: [ConsumerProfile] = []
    private(set) var requests: [SecretRequest] = []
    private(set) var receipts: [RequestReceipt] = []
    private(set) var isWorking = false
    var errorMessage: String?
    private(set) var configuredRemoteConsumerIDs: Set<ConsumerID> = []
    private(set) var remoteConnectionStates: [ConsumerID: RemoteConnectionState] = [:]
    private(set) var remoteProfileConfigurationIssue = false
    private(set) var lastRemoteConnectionCheckAt: Date?
    private(set) var recoveryConfiguration: RecoveryConfiguration?
    private(set) var telegramConfiguration: TelegramConfiguration?
    private(set) var telegramPairingCode: String?
    private(set) var telegramBotUsername: String?
    private(set) var telegramStatusMessage: String?
    private(set) var lastImportCount = 0
    private(set) var notificationsEnabled = false
    private(set) var companionConfiguration = CompanionConfiguration()
    private(set) var companionRegistrations: [CompanionDeviceRegistration] = []
    private(set) var companionStatusMessage: String?
    private(set) var companionPairingCode: String?

    let directories: AppDirectories
    private let metadataStore: FileMetadataStore
    private let inbox: FileRequestInbox
    private let receiptStore: FileReceiptStore
    private let secretStore: KeychainSecretStore
    private var coordinator: ApprovalCoordinator
    private let ownerAuthorizer: any OwnerPresenceAuthorizing
    private var remoteProfiles: [RemoteAgeProfile]
    private let remoteHostChecker: any RemoteHostChecking
    private let recoveryStore: FileRecoveryConfigurationStore
    private let telegramStore: FileTelegramApprovalStore
    private let telegramTokenStore: TelegramBotTokenStore
    private let telegramBot: any TelegramBotServing
    private let notificationService = RequestNotificationService()
    private let companionStore: FileCompanionConfigurationStore
    private let companionCloud: any CompanionCloudServing
    private let companionKeyStore = CompanionDeviceKeyStore()
    private var knownRequestIDs = Set<UUID>()
    private var knownReceiptIDs = Set<UUID>()
    private var promptedRequestIDs = Set<UUID>()
    private var monitoringTask: Task<Void, Never>?
    private(set) var pendingSecretPrompt: SecretRequest?
    private var hasCompletedInitialRefresh = false
    private var lastCompanionRefresh = Date.distantPast
    private var isProcessingCompanion = false
    private var lastRemoteConnectionCheckStartedAt = Date.distantPast
    private var remoteConnectionCheckTask: Task<Void, Never>?

    init(
        directories: AppDirectories = .standard,
        remoteHostChecker: any RemoteHostChecking = SSHRemoteHostChecker(),
        ownerAuthorizer: any OwnerPresenceAuthorizing = LocalOwnerPresenceAuthorizer(),
        telegramBot: any TelegramBotServing = TelegramBotAPI(),
        companionCloud: any CompanionCloudServing = CloudKitCompanionStore()
    ) {
        self.directories = directories
        metadataStore = FileMetadataStore(root: directories.metadata)
        inbox = FileRequestInbox(root: directories.inbox)
        receiptStore = FileReceiptStore(root: directories.receipts)
        recoveryStore = FileRecoveryConfigurationStore(root: directories.metadata)
        telegramStore = FileTelegramApprovalStore(root: directories.metadata)
        companionStore = FileCompanionConfigurationStore(root: directories.metadata)
        telegramTokenStore = TelegramBotTokenStore()
        self.telegramBot = telegramBot
        self.companionCloud = companionCloud
        self.ownerAuthorizer = ownerAuthorizer
        let keychain = KeychainSecretStore()
        secretStore = keychain
        let profiles: [RemoteAgeProfile]
        do {
            profiles = try FileRemoteAgeProfileStore(root: directories.metadata).profiles()
        } catch {
            profiles = []
            remoteProfileConfigurationIssue = true
        }
        remoteProfiles = profiles
        self.remoteHostChecker = remoteHostChecker
        configuredRemoteConsumerIDs = Set(profiles.map(\.id))
        let remoteInstaller: RemoteAgeSecretInstaller?
        if let allowlist = try? RemoteAgeAllowlist(profiles: profiles), !profiles.isEmpty {
            remoteInstaller = RemoteAgeSecretInstaller(
                allowlist: allowlist,
                encryptor: SystemAgeEncryptor(),
                transport: SSHRemoteAgeTransport()
            )
        } else {
            remoteInstaller = nil
        }
        coordinator = ApprovalCoordinator(
            secretStore: keychain,
            installer: RoutingSecretInstaller(remote: remoteInstaller)
        )
    }

    var guidedHostsConfigured: Bool {
        GuidedDestination.remoteCases.allSatisfy {
            guard let consumerID = ConsumerID(rawValue: $0.consumerIDValue) else { return false }
            return configuredRemoteConsumerIDs.contains(consumerID)
        }
    }

    var hasConfiguredRemoteDestinations: Bool {
        GuidedDestination.allCases.contains {
            guard $0 != .thisMac,
                  let consumerID = ConsumerID(rawValue: $0.consumerIDValue) else { return false }
            return configuredRemoteConsumerIDs.contains(consumerID)
        }
    }

    func startMonitoring() {
        guard monitoringTask == nil else { return }
        monitoringTask = Task { [weak self] in
            await self?.runMonitoringLoop()
        }
    }

    private func runMonitoringLoop() async {
        await refreshNotificationStatus()
        while !Task.isCancelled {
            await refresh()
            scheduleRemoteConnectionCheckIfNeeded()
            queueSecretPromptIfNeeded()
            await processTelegramApprovals()
            await processCompanion()
            do {
                try await Task.sleep(for: .seconds(3))
            } catch {
                return
            }
        }
    }

    func queueSecretPromptIfNeeded() {
        guard pendingSecretPrompt == nil,
              let request = requests.first(where: {
                  !hasSecret(for: $0) && !promptedRequestIDs.contains($0.id)
              }) else { return }
        promptedRequestIDs.insert(request.id)
        pendingSecretPrompt = request
    }

    func markRequestPrompted(_ request: SecretRequest) {
        promptedRequestIDs.insert(request.id)
        if pendingSecretPrompt?.id == request.id {
            pendingSecretPrompt = nil
        }
    }

    func takePendingSecretPrompt() -> SecretRequest? {
        guard let request = pendingSecretPrompt,
              requests.contains(where: { $0.id == request.id }),
              !hasSecret(for: request) else {
            pendingSecretPrompt = nil
            return nil
        }
        pendingSecretPrompt = nil
        return request
    }

    var isTestingRemoteConnections: Bool {
        remoteConnectionCheckTask != nil || remoteConnectionStates.values.contains(.checking)
    }

    var guidedConnectionsConfirmed: Bool {
        guidedHostsConfigured && GuidedDestination.remoteCases.allSatisfy {
            guard let consumerID = ConsumerID(rawValue: $0.consumerIDValue) else { return false }
            return remoteConnectionStates[consumerID] == .connected
        }
    }

    func connectionState(for destination: GuidedDestination) -> RemoteConnectionState? {
        guard destination != .thisMac,
              let consumerID = ConsumerID(rawValue: destination.consumerIDValue),
              configuredRemoteConsumerIDs.contains(consumerID) else {
            return nil
        }
        return remoteConnectionStates[consumerID] ?? .notTested
    }

    func testRemoteConnections() async {
        let guidedProfiles = GuidedDestination.allCases.compactMap { destination -> RemoteAgeProfile? in
            guard destination != .thisMac,
                  let consumerID = ConsumerID(rawValue: destination.consumerIDValue),
                  let targetID = TargetID(rawValue: destination.targetIDValue) else { return nil }
            return remoteProfiles.first {
                $0.id == consumerID && $0.targetID == targetID
            }
        }
        guard !guidedProfiles.isEmpty else {
            errorMessage = "Ask your AI to finish one destination before checking connections."
            return
        }
        lastRemoteConnectionCheckStartedAt = Date()
        for profile in guidedProfiles {
            remoteConnectionStates[profile.id] = .checking
        }
        let checker = remoteHostChecker
        await withTaskGroup(of: (RemoteAgeProfile, RemoteConnectionState).self) { group in
            for profile in guidedProfiles {
                group.addTask {
                    do {
                        _ = try await checker.check(profile)
                        return (profile, .connected)
                    } catch {
                        return (profile, .needsAttention)
                    }
                }
            }
            for await (profile, state) in group where remoteProfiles.contains(profile) {
                remoteConnectionStates[profile.id] = state
            }
        }
        lastRemoteConnectionCheckAt = Date()
    }

    func refresh() async {
        let metadataStore = metadataStore
        let inbox = inbox
        let receiptStore = receiptStore
        let recoveryStore = recoveryStore
        let telegramStore = telegramStore
        let directories = directories
        let remoteProfileStore = FileRemoteAgeProfileStore(root: directories.metadata)
        do {
            let snapshot = try await Task.detached(priority: .utility) {
                try directories.prepareInstallations()
                let builtInProfiles = try GuidedDestination.allCases.map {
                    try $0.consumerProfile(directories: directories)
                }
                try metadataStore.registerMissingConsumers(builtInProfiles)
                let remoteProfiles: [RemoteAgeProfile]
                let remoteProfilesValid: Bool
                do {
                    remoteProfiles = try remoteProfileStore.profiles()
                    remoteProfilesValid = true
                } catch {
                    remoteProfiles = []
                    remoteProfilesValid = false
                }
                return try (
                    metadataStore.secrets(),
                    metadataStore.consumers(),
                    inbox.pending(),
                    receiptStore.all(),
                    try recoveryStore.configuration(),
                    try telegramStore.state().configuration,
                    remoteProfiles,
                    remoteProfilesValid
                )
            }.value
            secrets = snapshot.0
            consumers = snapshot.1
            let finishedRequestIDs = Set(snapshot.3.map(\.requestID))
            let pendingRequests = snapshot.2.filter { !finishedRequestIDs.contains($0.id) }
            let pendingIDs = Set(pendingRequests.map(\.id))
            let receiptIDs = Set(snapshot.3.map(\.requestID))
            let newRequests = pendingRequests.filter { !knownRequestIDs.contains($0.id) }
            let newReceipts = snapshot.3.filter { !knownReceiptIDs.contains($0.requestID) }
            requests = pendingRequests
            receipts = snapshot.3
            recoveryConfiguration = snapshot.4
            telegramConfiguration = snapshot.5
            remoteProfileConfigurationIssue = !snapshot.7
            applyRemoteProfiles(snapshot.6)
            companionConfiguration = try companionStore.configuration()
            if telegramConfiguration == nil, telegramPairingCode == nil {
                try? telegramTokenStore.delete()
            }
            if hasCompletedInitialRefresh, notificationsEnabled {
                for request in newRequests {
                    await notificationService.notifyPending(destination: requestTitle(request))
                }
                for receipt in newReceipts {
                    await notificationService.notifyCompleted(
                        destination: receiptDestinationName(receipt),
                        wasDelivered: receipt.status == .verified
                    )
                }
            }
            knownRequestIDs = pendingIDs
            knownReceiptIDs = receiptIDs
            hasCompletedInitialRefresh = true
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func applyRemoteProfiles(_ profiles: [RemoteAgeProfile]) {
        guard profiles != remoteProfiles else { return }
        remoteProfiles = profiles
        configuredRemoteConsumerIDs = Set(profiles.map(\.id))
        remoteConnectionStates = [:]
        lastRemoteConnectionCheckStartedAt = .distantPast

        let remoteInstaller: RemoteAgeSecretInstaller?
        if let allowlist = try? RemoteAgeAllowlist(profiles: profiles), !profiles.isEmpty {
            remoteInstaller = RemoteAgeSecretInstaller(
                allowlist: allowlist,
                encryptor: SystemAgeEncryptor(),
                transport: SSHRemoteAgeTransport()
            )
        } else {
            remoteInstaller = nil
        }
        coordinator = ApprovalCoordinator(
            secretStore: secretStore,
            installer: RoutingSecretInstaller(remote: remoteInstaller)
        )
    }

    private func scheduleRemoteConnectionCheckIfNeeded() {
        guard hasConfiguredRemoteDestinations, remoteConnectionCheckTask == nil else { return }
        let interval: TimeInterval = guidedConnectionsConfirmed ? 60 : 15
        guard Date().timeIntervalSince(lastRemoteConnectionCheckStartedAt) >= interval else { return }
        lastRemoteConnectionCheckStartedAt = Date()
        remoteConnectionCheckTask = Task { [weak self] in
            guard let self else { return }
            await self.testRemoteConnections()
            self.remoteConnectionCheckTask = nil
        }
    }

    func saveSecret(for destination: GuidedDestination, value: Data) async -> Bool {
        guard !value.isEmpty else {
            errorMessage = "Enter a value to protect."
            return false
        }
        isWorking = true
        defer { isWorking = false }
        do {
            let secretID = try SecretID(validating: destination.secretIDValue)
            let previousMetadata = secrets.first { $0.id == secretID }
            let metadata = SecretMetadata(
                secretID: secretID,
                displayName: destination.secretDisplayName,
                kind: .other,
                materialKind: previousMetadata?.materialKind ?? .single,
                createdAt: previousMetadata?.createdAt ?? Date(),
                ownerName: previousMetadata?.ownerName,
                projectName: previousMetadata?.projectName,
                environmentName: previousMetadata?.environmentName,
                rotationDueAt: previousMetadata?.rotationDueAt,
                expiresAt: previousMetadata?.expiresAt,
                allowsTelegramApproval: previousMetadata?.allowsTelegramApproval ?? false,
                allowsCompanionApproval: previousMetadata?.allowsCompanionApproval ?? false
            )
            let previousValue: Data?
            if previousMetadata != nil {
                guard let value = try await secretStore.read(
                    id: secretID,
                    reason: "Replace \(metadata.displayName) in KeyCourier"
                ) else {
                    throw KeyCourierError.invalidMetadata
                }
                previousValue = value
            } else {
                previousValue = nil
            }
            do {
                try await secretStore.save(
                    value,
                    id: secretID,
                    allowsRemoteApproval: metadata.allowsTelegramApproval || metadata.allowsCompanionApproval
                )
                try metadataStore.save(metadata)
            } catch {
                if let previousMetadata, let previousValue {
                    try? await secretStore.save(
                        previousValue,
                        id: secretID,
                        allowsRemoteApproval: previousMetadata.allowsTelegramApproval
                            || previousMetadata.allowsCompanionApproval
                    )
                } else {
                    try? await secretStore.delete(
                        id: secretID,
                        reason: "Roll back an incomplete KeyCourier credential"
                    )
                }
                throw error
            }
            await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func addSecret(
        id: String,
        displayName: String,
        kind: SecretKind,
        value: Data,
        materialKind: SecretMaterialKind = .single,
        ownerName: String? = nil,
        projectName: String? = nil,
        environmentName: String? = nil,
        rotationDueAt: Date? = nil,
        expiresAt: Date? = nil,
        allowsTelegramApproval: Bool = false,
        allowsCompanionApproval: Bool = false
    ) async -> Bool {
        guard !value.isEmpty else {
            errorMessage = "Enter a value to protect."
            return false
        }
        isWorking = true
        defer { isWorking = false }
        do {
            let secretID = try SecretID(validating: id)
            guard !GuidedDestination.allCases.contains(where: { $0.secretIDValue == secretID.rawValue }) else {
                errorMessage = "That short name is reserved for guided setup."
                return false
            }
            guard !secrets.contains(where: { $0.id == secretID }) else {
                errorMessage = "That secret ID already exists."
                return false
            }
            let metadata = SecretMetadata(
                secretID: secretID,
                displayName: normalizedCredentialName(displayName, for: secretID),
                kind: kind,
                materialKind: materialKind,
                ownerName: ownerName,
                projectName: projectName,
                environmentName: environmentName,
                rotationDueAt: rotationDueAt,
                expiresAt: expiresAt,
                allowsTelegramApproval: allowsTelegramApproval,
                allowsCompanionApproval: allowsCompanionApproval
            )
            do {
                try await secretStore.save(
                    value,
                    id: secretID,
                    allowsRemoteApproval: allowsTelegramApproval || allowsCompanionApproval
                )
                try metadataStore.save(metadata)
            } catch {
                try? await secretStore.delete(
                    id: secretID,
                    reason: "Roll back an incomplete KeyCourier credential"
                )
                throw error
            }
            await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func deleteSecret(_ metadata: SecretMetadata) async {
        isWorking = true
        defer { isWorking = false }
        do {
            guard let previousValue = try await secretStore.read(
                id: metadata.id,
                reason: "Delete \(metadata.displayName) from KeyCourier"
            ) else {
                throw KeyCourierError.invalidMetadata
            }
            try metadataStore.removeSecret(id: metadata.id)
            do {
                try await secretStore.delete(id: metadata.id, reason: "Delete a KeyCourier secret")
            } catch {
                try? metadataStore.save(metadata)
                try? await secretStore.save(
                    previousValue,
                    id: metadata.id,
                    allowsRemoteApproval: metadata.allowsTelegramApproval
                        || metadata.allowsCompanionApproval
                )
                throw error
            }
            await refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func addConsumer(
        id: String,
        displayName: String,
        targetID: String,
        path: String,
        variable: String
    ) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            let consumerID = try ConsumerID(validating: id)
            guard !GuidedDestination.allCases.contains(where: { $0.consumerIDValue == consumerID.rawValue }) else {
                errorMessage = "That short name is reserved for guided setup."
                return false
            }
            let profile = try ConsumerProfile(
                id: consumerID,
                displayName: displayName,
                targetID: TargetID(validating: targetID),
                destination: .dotenv(path: path, variable: variable)
            )
            try metadataStore.save(profile)
            await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func deleteConsumer(_ profile: ConsumerProfile) async {
        do {
            try metadataStore.removeConsumer(id: profile.id)
            await refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func approve(_ request: SecretRequest) async {
        isWorking = true
        defer { isWorking = false }
        if let metadata = secrets.first(where: { $0.id == request.secretID }),
           metadata.allowsTelegramApproval || metadata.allowsCompanionApproval {
            do {
                try await ownerAuthorizer.authorize(reason: "Approve KeyCourier delivery")
            } catch {
                errorMessage = "Approval was cancelled."
                return
            }
        }
        let receipt = await coordinator.approve(request, consumers: consumers, secrets: secrets)
        finish(request, with: receipt)
        await refresh()
    }

    func hasSecret(for request: SecretRequest) -> Bool {
        secrets.contains { $0.id == request.secretID }
    }

    func saveRequestedCredential(_ entry: CredentialEntry, for request: SecretRequest) async -> Bool {
        switch entry {
        case .single(let value):
            return await saveRequestedSecret(value, for: request, materialKind: .single)
        case .usernamePassword(let username, let password):
            do {
                let value = try CompanionCredentialMaterial
                    .usernamePassword(username: username, password: password)
                    .deliveryData()
                return await saveRequestedSecret(
                    value,
                    for: request,
                    kind: .password,
                    materialKind: .usernamePassword
                )
            } catch {
                errorMessage = error.localizedDescription
                return false
            }
        }
    }

    func saveRequestedSecret(
        _ value: Data,
        for request: SecretRequest,
        kind: SecretKind? = nil,
        materialKind: SecretMaterialKind = .single
    ) async -> Bool {
        guard !value.isEmpty else {
            errorMessage = "Paste a key or password first."
            return false
        }
        do {
            try request.validate()
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
        guard !hasSecret(for: request) else {
            errorMessage = "That credential is already saved. Use Edit to replace its value."
            return false
        }
        isWorking = true
        defer { isWorking = false }
        let metadata = SecretMetadata(
            secretID: request.secretID,
            displayName: requestedSecretName(request),
            kind: kind ?? requestedSecretKind(request),
            materialKind: materialKind,
            allowsCompanionApproval: false
        )
        do {
            try await secretStore.save(
                value,
                id: request.secretID,
                allowsRemoteApproval: false
            )
            do {
                try metadataStore.save(metadata)
            } catch {
                try? await secretStore.delete(
                    id: request.secretID,
                    reason: "Roll back an incomplete KeyCourier credential"
                )
                throw error
            }
            let receipt = await coordinator.approve(
                request,
                consumers: consumers,
                secrets: secrets + [metadata]
            )
            finish(request, with: receipt)
            await refresh()
            guard receipt.status == .verified else {
                errorMessage = "The credential was saved, but delivery did not complete. Check Activity for the result."
                return false
            }
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func replaceCredential(_ entry: CredentialEntry, for metadata: SecretMetadata) async -> Bool {
        var updatedMetadata = metadata
        updatedMetadata.materialKind = entry.materialKind
        if entry.materialKind == .usernamePassword {
            updatedMetadata.kind = .password
        }
        switch entry {
        case .single(let value):
            guard !value.isEmpty else {
                errorMessage = "Paste a replacement key or password first."
                return false
            }
            return await updateSecretMetadata(updatedMetadata, replacementValue: value)
        case .usernamePassword(let username, let password):
            do {
                let value = try CompanionCredentialMaterial
                    .usernamePassword(username: username, password: password)
                    .deliveryData()
                return await updateSecretMetadata(updatedMetadata, replacementValue: value)
            } catch {
                errorMessage = error.localizedDescription
                return false
            }
        }
    }

    private func requestedSecretName(_ request: SecretRequest) -> String {
        if let destination = GuidedDestination.matching(
            secretID: request.secretID,
            consumerID: request.consumerID,
            targetID: request.targetID
        ) {
            return destination.secretDisplayName
        }
        return request.secretID.rawValue
            .split(whereSeparator: { $0 == "-" || $0 == "_" || $0 == "." })
            .map { $0.capitalized }
            .joined(separator: " ")
    }

    private func normalizedCredentialName(_ name: String, for secretID: SecretID) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return "Credential \(secretID.rawValue.suffix(6).uppercased())"
        }
        return trimmed
    }

    private func requestedSecretKind(_ request: SecretRequest) -> SecretKind {
        let id = request.secretID.rawValue
        return id.contains("password") || id.contains("passwd") ? .password : .apiKey
    }

    func deny(_ request: SecretRequest) async {
        finish(request, with: coordinator.deny(request))
        await refresh()
    }

    private func finish(_ request: SecretRequest, with receipt: RequestReceipt) {
        do {
            try receiptStore.record(receipt)
            try inbox.remove(request.id)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func updateSecretMetadata(_ updated: SecretMetadata, replacementValue: Data? = nil) async -> Bool {
        guard let previous = secrets.first(where: { $0.id == updated.id }) else {
            errorMessage = "That credential could not be found."
            return false
        }
        if (previous.allowsTelegramApproval != updated.allowsTelegramApproval
            || previous.allowsCompanionApproval != updated.allowsCompanionApproval
            || previous.materialKind != updated.materialKind),
           replacementValue?.isEmpty != false {
            errorMessage = "Re-enter the credential value when changing its format or remote approval access."
            return false
        }
        isWorking = true
        defer { isWorking = false }
        do {
            if let replacementValue, !replacementValue.isEmpty {
                guard let previousValue = try await secretStore.read(
                    id: previous.id,
                    reason: "Replace \(previous.displayName) in KeyCourier"
                ) else {
                    throw KeyCourierError.invalidMetadata
                }
                do {
                    try await secretStore.save(
                        replacementValue,
                        id: updated.id,
                        allowsRemoteApproval: updated.allowsTelegramApproval || updated.allowsCompanionApproval
                    )
                    try metadataStore.save(updated)
                } catch {
                    // A Keychain update can fail after touching one of its
                    // approval services. Restore the prior bytes and policy
                    // before surfacing the failure.
                    try? await secretStore.save(
                        previousValue,
                        id: previous.id,
                        allowsRemoteApproval: previous.allowsTelegramApproval
                            || previous.allowsCompanionApproval
                    )
                    throw error
                }
            } else {
                try metadataStore.save(updated)
            }
            await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func importDotenv(
        from url: URL,
        projectName: String?,
        environmentName: String?
    ) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            let drafts = try DotenvSecretImporter.parse(contentsOf: url)
            let existingIDs = Set(secrets.map(\.id))
            let newDrafts = drafts.filter { !existingIDs.contains($0.id) }
            guard !newDrafts.isEmpty else {
                errorMessage = "Every credential in that file is already saved."
                return false
            }
            var saved: [SecretMetadata] = []
            do {
                for draft in newDrafts {
                    let metadata = SecretMetadata(
                        secretID: draft.id,
                        displayName: draft.displayName,
                        kind: .other,
                        projectName: projectName,
                        environmentName: environmentName
                    )
                    do {
                        try await secretStore.save(draft.value, id: draft.id)
                        try metadataStore.save(metadata)
                    } catch {
                        try? await secretStore.delete(
                            id: draft.id,
                            reason: "Roll back an incomplete KeyCourier import"
                        )
                        throw error
                    }
                    saved.append(metadata)
                }
            } catch {
                for metadata in saved {
                    try? await secretStore.delete(id: metadata.id, reason: "Roll back KeyCourier import")
                    try? metadataStore.removeSecret(id: metadata.id)
                }
                throw error
            }
            lastImportCount = saved.count
            await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func saveRecoveryRecipients(_ recipients: [String]) async -> Bool {
        do {
            let configuration = try RecoveryConfiguration(ageRecipients: recipients)
            try recoveryStore.save(configuration)
            recoveryConfiguration = configuration
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func refreshNotificationStatus() async {
        notificationsEnabled = await notificationService.isAuthorised()
    }

    func enableNotifications() async {
        notificationsEnabled = await notificationService.requestPermission()
        if !notificationsEnabled {
            errorMessage = "Notifications are off. You can enable them in System Settings."
        }
    }

    func exportRecoveryBackup(to url: URL) async -> Bool {
        guard let recoveryConfiguration else {
            errorMessage = "Add an offline recovery recipient first."
            return false
        }
        isWorking = true
        defer { isWorking = false }
        do {
            try await ownerAuthorizer.authorize(reason: "Export an encrypted KeyCourier recovery backup")
            var records: [SecretBackupRecord] = []
            for metadata in secrets {
                guard let value = try await secretStore.read(
                    id: metadata.id,
                    reason: "Include \(metadata.displayName) in the encrypted recovery backup"
                ) else {
                    throw KeyCourierError.invalidBackup
                }
                records.append(SecretBackupRecord(metadata: metadata, secret: value))
            }
            let bundle = try SecretBackupBundle(records: records)
            let encrypted = try SystemAgeEncryptor().encrypt(
                bundle.encoded(),
                recipients: recoveryConfiguration.ageRecipients
            )
            try RecoveryBackupFile.write(encrypted, to: url)
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func restoreRecoveryBackup(from url: URL, identityURL: URL) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            try await ownerAuthorizer.authorize(reason: "Restore a KeyCourier recovery backup")
            let encrypted = try RecoveryBackupFile.read(from: url)
            let plaintext = try SystemAgeDecryptor(identityPath: identityURL.path).decrypt(encrypted)
            let bundle = try SecretBackupBundle.decode(plaintext)
            for record in bundle.records {
                let previous = secrets.first { $0.id == record.metadata.id }
                let previousValue: Data?
                if let previous {
                    previousValue = try await secretStore.read(
                        id: previous.id,
                        reason: "Restore \(record.metadata.displayName) in KeyCourier"
                    )
                } else {
                    previousValue = nil
                }
                do {
                    try await secretStore.save(
                        record.secret,
                        id: record.metadata.id,
                        allowsRemoteApproval: record.metadata.allowsTelegramApproval
                            || record.metadata.allowsCompanionApproval
                    )
                    try metadataStore.save(record.metadata)
                } catch {
                    if let previous, let previousValue {
                        try? await secretStore.save(
                            previousValue,
                            id: previous.id,
                            allowsRemoteApproval: previous.allowsTelegramApproval
                                || previous.allowsCompanionApproval
                        )
                        try? metadataStore.save(previous)
                    } else {
                        try? await secretStore.delete(
                            id: record.metadata.id,
                            reason: "Roll back an incomplete KeyCourier restore"
                        )
                        try? metadataStore.removeSecret(id: record.metadata.id)
                    }
                    throw error
                }
            }
            await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func startTelegramPairing(botToken: String) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            let token = try TelegramBotTokenStore.validatedToken(botToken)
            let identity = try await telegramBot.identity(token: token)
            try telegramTokenStore.save(token)
            telegramBotUsername = identity.username
            telegramPairingCode = String(
                UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12)
            ).lowercased()
            telegramStatusMessage = "Send the pairing command to @\(identity.username)."
            return true
        } catch {
            try? telegramTokenStore.delete()
            errorMessage = error.localizedDescription
            return false
        }
    }

    func completeTelegramPairing() async -> Bool {
        guard let code = telegramPairingCode,
              let username = telegramBotUsername,
              let token = try? telegramTokenStore.read() else {
            errorMessage = KeyCourierError.telegramNotConfigured.localizedDescription
            return false
        }
        isWorking = true
        defer { isWorking = false }
        do {
            guard let pairing = try await telegramBot.findPairing(token: token, code: code, after: 0) else {
                telegramStatusMessage = "Pairing message not found yet. Send /pair \(code) to @\(username), then try again."
                return false
            }
            let configuration = try TelegramConfiguration(
                chatID: pairing.chatID,
                userID: pairing.userID,
                botUsername: username,
                lastUpdateID: pairing.updateID
            )
            try telegramStore.saveConfiguration(configuration)
            telegramConfiguration = configuration
            telegramPairingCode = nil
            telegramStatusMessage = "Telegram approvals are ready."
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func disconnectTelegram() async {
        do {
            try telegramStore.saveConfiguration(nil)
            try telegramTokenStore.delete()
            telegramConfiguration = nil
            telegramPairingCode = nil
            telegramBotUsername = nil
            telegramStatusMessage = "Telegram was disconnected."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func processTelegramApprovals() async {
        guard let configuration = telegramConfiguration,
              configuration.isEnabled,
              let token = try? telegramTokenStore.read() else { return }
        do {
            let state = try telegramStore.state()
            for request in requests {
                guard secrets.first(where: { $0.id == request.secretID })?.allowsTelegramApproval == true else {
                    continue
                }
                let record = try telegramStore.preparedApproval(for: request)
                guard record.state == .prepared, record.sendAttempts < 3 else { continue }
                do {
                    try await telegramBot.sendApproval(
                        token: token,
                        chatID: configuration.chatID,
                        title: requestCredentialName(request),
                        destination: requestTitle(request),
                        client: request.client.rawValue.capitalized,
                        expiresAt: request.expiresAt,
                        record: record
                    )
                    try telegramStore.markSent(requestID: request.id)
                } catch {
                    try? telegramStore.markSendFailed(requestID: request.id)
                }
            }

            let lastUpdateID = state.configuration?.lastUpdateID ?? configuration.lastUpdateID
            let batch = try await telegramBot.approvalEvents(
                token: token,
                after: lastUpdateID
            )
            for event in batch.events {
                do {
                    let result = try telegramStore.consume(
                        nonce: event.nonce,
                        action: event.action,
                        chatID: event.chatID,
                        userID: event.userID
                    )
                    guard let request = requests.first(where: { $0.id == result.0 }) else {
                        await telegramBot.answerCallback(
                            token: token,
                            callbackQueryID: event.callbackQueryID,
                            text: "This request is no longer pending."
                        )
                        continue
                    }
                    if result.1 == .approve {
                        await approveFromTelegram(request)
                        await telegramBot.answerCallback(
                            token: token,
                            callbackQueryID: event.callbackQueryID,
                            text: "Decision received. Check KeyCourier Activity for the result."
                        )
                    } else {
                        await deny(request)
                        await telegramBot.answerCallback(
                            token: token,
                            callbackQueryID: event.callbackQueryID,
                            text: "Declined."
                        )
                    }
                } catch {
                    await telegramBot.answerCallback(
                        token: token,
                        callbackQueryID: event.callbackQueryID,
                        text: "This approval is invalid or has already been used."
                    )
                }
            }
            if batch.latestUpdateID > lastUpdateID {
                try telegramStore.setLastUpdateID(batch.latestUpdateID)
            }
            let finished = Set(receipts.map(\.requestID))
            try telegramStore.removeFinished(requestIDs: finished)
            telegramConfiguration = try telegramStore.state().configuration
        } catch {
            telegramStatusMessage = "Telegram is temporarily unavailable. KeyCourier will retry safely."
        }
    }

    var remoteRecipientCounts: [(name: String, count: Int)] {
        remoteProfiles.map { ($0.displayName, $0.ageRecipients.count) }
    }

    private func approveFromTelegram(_ request: SecretRequest) async {
        guard secrets.first(where: { $0.id == request.secretID })?.allowsTelegramApproval == true else {
            return
        }
        isWorking = true
        defer { isWorking = false }
        let receipt = await coordinator.approve(request, consumers: consumers, secrets: secrets)
        finish(request, with: receipt)
        await refresh()
    }

    func setCompanionEnabled(_ isEnabled: Bool) async {
        do {
            if isEnabled {
                _ = try companionKeyStore.loadOrCreate()
                try await companionCloud.requireAvailableAccount()
            } else {
                try await companionCloud.purgeTransientData()
                try await companionCloud.replaceCredentialSummaries([])
                try await companionCloud.replaceRequests([])
            }
            companionConfiguration = try companionStore.setEnabled(isEnabled)
            companionStatusMessage = isEnabled
                ? "Companion pairing is ready. Open KeyCourier on your iPhone to register it."
                : "iPhone companion is off."
            lastCompanionRefresh = .distantPast
            if isEnabled { await processCompanion(force: true) }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func approveCompanionRegistration(_ registration: CompanionDeviceRegistration) async {
        guard companionConfiguration.trustedDevice == nil
                || companionConfiguration.trustedDevice?.id == registration.id else {
            errorMessage = "Remove the currently paired iPhone before approving another one."
            return
        }
        do {
            try await ownerAuthorizer.authorize(reason: "Pair this iPhone with KeyCourier")
            let accountIdentifier = try await companionCloud.accountIdentifier()
            let identity = try companionKeyStore.loadOrCreate()
            let macRegistration = try CompanionCrypto.registration(
                deviceID: identity.id,
                deviceName: Host.current().localizedName ?? "KeyCourier Mac",
                keys: identity.keys
            )
            var approvedRegistration = registration
            approvedRegistration.status = .approved
            approvedRegistration.macKeyAgreementPublicKey = macRegistration.keyAgreementPublicKey
            approvedRegistration.macSigningPublicKey = macRegistration.signingPublicKey
            do {
                companionConfiguration = try companionStore.trust(
                    approvedRegistration,
                    accountIdentifier: accountIdentifier
                )
            } catch {
                if (try? companionStore.configuration())?.trustedDevice?.id == registration.id {
                    companionConfiguration = (try? companionStore.requireRePair())
                        ?? CompanionConfiguration()
                }
                throw error
            }
            do {
                try await companionCloud.purgeTransientData()
                try await companionCloud.updateDeviceRegistration(
                    id: registration.id,
                    status: .approved,
                    macKeyAgreementPublicKey: macRegistration.keyAgreementPublicKey,
                    macSigningPublicKey: macRegistration.signingPublicKey
                )
                companionPairingCode = try CompanionCrypto.pairingCode(for: approvedRegistration)
                companionRegistrations.removeAll { $0.id == registration.id }
                companionStatusMessage = "\(registration.deviceName) is paired."
            } catch {
                try? await companionCloud.updateDeviceRegistration(
                    id: registration.id,
                    status: .denied,
                    macKeyAgreementPublicKey: nil,
                    macSigningPublicKey: nil
                )
                companionConfiguration = (try? companionStore.requireRePair())
                    ?? CompanionConfiguration()
                companionPairingCode = nil
                throw error
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func declineCompanionRegistration(_ registration: CompanionDeviceRegistration) async {
        do {
            try await companionCloud.updateDeviceRegistration(
                id: registration.id,
                status: .denied,
                macKeyAgreementPublicKey: nil,
                macSigningPublicKey: nil
            )
            companionRegistrations.removeAll { $0.id == registration.id }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func removeTrustedCompanion() async {
        guard let trusted = companionConfiguration.trustedDevice else { return }
        do {
            try await ownerAuthorizer.authorize(reason: "Remove the paired KeyCourier iPhone")
            let accountIdentifier = try await companionCloud.accountIdentifier()
            guard companionConfiguration.isBound(to: accountIdentifier) else {
                companionConfiguration = try companionStore.requireRePair()
                companionRegistrations = []
                companionPairingCode = nil
                companionStatusMessage = "Pairing was reset. Register this iPhone again."
                return
            }
            try await companionCloud.updateDeviceRegistration(
                id: trusted.id,
                status: .denied,
                macKeyAgreementPublicKey: nil,
                macSigningPublicKey: nil
            )
            try await companionCloud.purgeTransientData()
            try await companionCloud.replaceCredentialSummaries([])
            try await companionCloud.replaceRequests([])
            companionConfiguration = try companionStore.removeTrustedDevice()
            companionPairingCode = nil
            companionStatusMessage = "The iPhone was removed. Its future approvals will be rejected."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func processCompanion(force: Bool = false) async {
        guard companionConfiguration.isEnabled else { return }
        guard force || Date().timeIntervalSince(lastCompanionRefresh) >= 10 else { return }
        guard !isProcessingCompanion else { return }
        isProcessingCompanion = true
        defer { isProcessingCompanion = false }
        lastCompanionRefresh = Date()
        do {
            let accountIdentifier = try await companionCloud.accountIdentifier()
            if companionConfiguration.trustedDevice != nil,
               !companionConfiguration.isBound(to: accountIdentifier) {
                companionConfiguration = try companionStore.requireRePair()
                companionRegistrations = []
                companionPairingCode = nil
                companionStatusMessage = "The iCloud account changed. Pair this iPhone again."
                return
            }
            let identity = try companionKeyStore.loadOrCreate()
            let registrations = try await companionCloud.deviceRegistrations()
            companionRegistrations = registrations.filter {
                $0.status == .pending && $0.id != companionConfiguration.trustedDevice?.id
            }

            guard let trusted = companionConfiguration.trustedDevice else {
                companionPairingCode = nil
                companionStatusMessage = companionRegistrations.isEmpty
                    ? "Waiting for an iPhone registration."
                    : "Review the iPhone registration below."
                return
            }

            let macRegistration = try CompanionCrypto.registration(
                deviceID: identity.id,
                deviceName: Host.current().localizedName ?? "KeyCourier Mac",
                keys: identity.keys
            )
            let macPublicKey = macRegistration.keyAgreementPublicKey
            let macSigningPublicKey = macRegistration.signingPublicKey
            var codeRegistration = trusted.registration
            codeRegistration.status = .approved
            codeRegistration.macKeyAgreementPublicKey = macPublicKey
            codeRegistration.macSigningPublicKey = macSigningPublicKey
            companionPairingCode = try CompanionCrypto.pairingCode(for: codeRegistration)

            guard let remoteRegistration = registrations.first(where: { $0.id == trusted.id }),
                  remoteRegistration.status == .approved,
                  remoteRegistration.signingPublicKey == trusted.registration.signingPublicKey,
                  remoteRegistration.keyAgreementPublicKey == trusted.registration.keyAgreementPublicKey,
                  remoteRegistration.macKeyAgreementPublicKey == macPublicKey,
                  remoteRegistration.macSigningPublicKey == macSigningPublicKey else {
                companionConfiguration = try companionStore.requireRePair()
                companionRegistrations = registrations.filter {
                    $0.status == .pending && $0.id != trusted.id
                }
                companionPairingCode = nil
                companionStatusMessage = "The iPhone pairing record changed. Pair this iPhone again."
                return
            }

            let summaries = try requests.compactMap { request -> CompanionRequestSummary? in
                guard let metadata = secrets.first(where: { $0.id == request.secretID }),
                      metadata.allowsCompanionApproval else { return nil }
                let summary = try CompanionRequestSummary(
                    requestID: request.id,
                    clientName: request.client.rawValue.capitalized,
                    credentialName: metadata.displayName,
                    destinationName: requestTitle(request),
                    reason: request.reason,
                    createdAt: request.createdAt,
                    expiresAt: request.expiresAt
                )
                return try CompanionCrypto.sign(summary, keys: identity.keys)
            }
            let credentialSummaries = try secrets.filter(\.allowsCompanionApproval).map {
                try CompanionCredentialSummary(
                    secretID: $0.id.rawValue,
                    displayName: $0.displayName,
                    kind: $0.kind.rawValue,
                    materialKind: companionMaterialKind(for: $0.materialKind)
                )
            }
            try await companionCloud.replaceCredentialSummaries(credentialSummaries)
            try await companionCloud.replaceRequests(summaries)
            try await processCompanionDecisions(trusted: trusted, summaries: summaries)
            try await processCompanionSecretEnvelopes(trusted: trusted, identity: identity)
            companionStatusMessage = summaries.isEmpty
                ? "Companion is connected. No phone-eligible requests are waiting."
                : "Companion is connected with \(summaries.count) request(s) waiting."
        } catch {
            companionStatusMessage = "Companion could not reach iCloud. It will retry safely."
        }
    }

    private func processCompanionDecisions(
        trusted: TrustedCompanionDevice,
        summaries: [CompanionRequestSummary]
    ) async throws {
        let summariesByID = Dictionary(uniqueKeysWithValues: summaries.map { ($0.id, $0) })
        for decision in try await companionCloud.decisions() {
            if companionConfiguration.processedDecisionIDs.contains(decision.id) {
                try? await companionCloud.deleteDecision(id: decision.id)
                continue
            }

            let request: SecretRequest
            do {
                guard decision.deviceID == trusted.id else {
                    throw CompanionProtocolError.invalidSignature
                }
                try CompanionCrypto.verify(
                    decision,
                    signingPublicKey: trusted.registration.signingPublicKey
                )
                guard let summary = summariesByID[decision.requestID],
                      decision.requestDigest == (try summary.digest()) else {
                    throw CompanionProtocolError.invalidSignature
                }
                guard let pending = requests.first(where: { $0.id == decision.requestID }),
                      secrets.first(where: { $0.id == pending.secretID })?.allowsCompanionApproval == true else {
                    throw CompanionProtocolError.invalidSignature
                }
                request = pending
            } catch {
                companionStatusMessage = "An invalid or expired companion decision was rejected."
                companionConfiguration = try companionStore.markDecisionProcessed(decision.id)
                try? await companionCloud.deleteDecision(id: decision.id)
                continue
            }

            if decision.action == .approve {
                await approveFromCompanion(request)
            } else {
                await deny(request)
            }

            companionConfiguration = try companionStore.markDecisionProcessed(decision.id)
            try? await companionCloud.deleteDecision(id: decision.id)
            try? await companionCloud.deleteRequest(id: decision.requestID)
        }
    }

    private func processCompanionSecretEnvelopes(
        trusted: TrustedCompanionDevice,
        identity: CompanionDeviceIdentity
    ) async throws {
        for envelope in try await companionCloud.secretEnvelopes() {
            if companionConfiguration.processedEnvelopeIDs.contains(envelope.id) {
                try? await companionCloud.deleteSecretEnvelope(id: envelope.id)
                continue
            }
            var consumeEnvelope = false
            do {
                guard envelope.deviceID == trusted.id else {
                    throw CompanionProtocolError.invalidSignature
                }
                let payload = try CompanionCrypto.open(
                    envelope,
                    recipientKeys: identity.keys,
                    senderSigningPublicKey: trusted.registration.signingPublicKey
                )
                try await importCompanionSecret(payload)
                consumeEnvelope = true
            } catch {
                consumeEnvelope = shouldConsumeCompanionEnvelope(after: error)
                companionStatusMessage = consumeEnvelope
                    ? "An invalid companion credential was rejected."
                    : "The companion credential could not be saved yet. KeyCourier will retry safely."
            }
            guard consumeEnvelope else { continue }
            companionConfiguration = try companionStore.markEnvelopeProcessed(envelope.id)
            try? await companionCloud.deleteSecretEnvelope(id: envelope.id)
        }
    }

    private func shouldConsumeCompanionEnvelope(after error: Error) -> Bool {
        switch error {
        case CompanionProtocolError.invalidRecord,
             CompanionProtocolError.invalidSignature,
             CompanionProtocolError.expired,
             CompanionProtocolError.decryptionFailed,
             KeyCourierError.invalidIdentifier,
             KeyCourierError.invalidMetadata,
             KeyCourierError.malformedSecretValue:
            return true
        default:
            return false
        }
    }

    private func importCompanionSecret(_ payload: CompanionSecretPayload) async throws {
        let secretID = try SecretID(validating: payload.secretID)
        let value = try payload.deliveryData()
        if payload.replacesExisting {
            guard let existing = secrets.first(where: { $0.id == secretID }) else {
                throw KeyCourierError.invalidMetadata
            }
            guard existing.allowsCompanionApproval else {
                throw KeyCourierError.invalidMetadata
            }
            var updated = existing
            updated.kind = materialKind(for: payload.material, existing: existing.kind)
            updated.materialKind = secretMaterialKind(for: payload.material)
            updated.updatedAt = Date()
            guard let previousValue = try await secretStore.read(
                id: existing.id,
                reason: "Replace \(existing.displayName) from iPhone"
            ) else {
                throw KeyCourierError.invalidMetadata
            }
            do {
                try await secretStore.save(
                    value,
                    id: secretID,
                    allowsRemoteApproval: existing.allowsTelegramApproval || existing.allowsCompanionApproval
                )
                do {
                    try metadataStore.save(updated)
                } catch {
                    try? await secretStore.save(
                        previousValue,
                        id: existing.id,
                        allowsRemoteApproval: existing.allowsTelegramApproval
                            || existing.allowsCompanionApproval
                    )
                    throw error
                }
            } catch {
                try? await secretStore.save(
                    previousValue,
                    id: existing.id,
                    allowsRemoteApproval: existing.allowsTelegramApproval
                        || existing.allowsCompanionApproval
                )
                throw error
            }
            await refresh()
            return
        }
        guard !GuidedDestination.allCases.contains(where: { $0.secretIDValue == secretID.rawValue }),
              !secrets.contains(where: { $0.id == secretID }) else {
            throw KeyCourierError.invalidMetadata
        }
        guard let kind = SecretKind(rawValue: payload.kind) else {
            throw KeyCourierError.invalidMetadata
        }
        let metadata = SecretMetadata(
            secretID: secretID,
            displayName: payload.displayName,
            kind: kind,
            materialKind: secretMaterialKind(for: payload.material),
            ownerName: payload.ownerName,
            projectName: payload.projectName,
            environmentName: payload.environmentName,
            rotationDueAt: payload.rotationDueAt,
            expiresAt: payload.expiresAt,
            allowsCompanionApproval: true
        )
        do {
            try await secretStore.save(value, id: secretID, allowsRemoteApproval: true)
            do {
                try metadataStore.save(metadata)
            } catch {
                try? await secretStore.delete(
                    id: secretID,
                    reason: "Roll back an incomplete iPhone credential"
                )
                throw error
            }
        } catch {
            throw error
        }
        await refresh()
    }

    private func companionMaterialKind(for materialKind: SecretMaterialKind) -> CompanionCredentialMaterialKind {
        switch materialKind {
        case .single: .single
        case .usernamePassword: .usernamePassword
        }
    }

    private func secretMaterialKind(for material: CompanionCredentialMaterial) -> SecretMaterialKind {
        switch material {
        case .single: .single
        case .usernamePassword: .usernamePassword
        }
    }

    private func materialKind(
        for material: CompanionCredentialMaterial,
        existing: SecretKind
    ) -> SecretKind {
        switch material {
        case .single:
            existing
        case .usernamePassword:
            .password
        }
    }

    private func approveFromCompanion(_ request: SecretRequest) async {
        guard secrets.first(where: { $0.id == request.secretID })?.allowsCompanionApproval == true else {
            return
        }
        isWorking = true
        defer { isWorking = false }
        let receipt = await coordinator.approve(request, consumers: consumers, secrets: secrets)
        finish(request, with: receipt)
        await refresh()
    }
}
