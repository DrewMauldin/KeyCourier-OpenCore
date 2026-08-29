import CloudKit
import Foundation
import Security

public protocol CompanionCloudServing: Sendable {
    /// Returns the opaque CloudKit user record name for the active account.
    /// Implementations that cannot expose an account identity fail closed;
    /// the default keeps older test doubles source-compatible.
    func accountIdentifier() async throws -> String
    func requireAvailableAccount() async throws
    func saveDeviceRegistration(_ registration: CompanionDeviceRegistration) async throws
    func deviceRegistration(id: UUID) async throws -> CompanionDeviceRegistration?
    func deviceRegistrations() async throws -> [CompanionDeviceRegistration]
    func updateDeviceRegistration(
        id: UUID,
        status: CompanionRegistrationStatus,
        macKeyAgreementPublicKey: Data?,
        macSigningPublicKey: Data?
    ) async throws
    func replaceCredentialSummaries(_ credentials: [CompanionCredentialSummary]) async throws
    func credentialSummaries() async throws -> [CompanionCredentialSummary]
    func purgeTransientData() async throws
    func replaceRequests(_ requests: [CompanionRequestSummary]) async throws
    func pendingRequests(at date: Date) async throws -> [CompanionRequestSummary]
    func saveDecision(_ decision: CompanionDecision) async throws
    func decisions() async throws -> [CompanionDecision]
    func deleteDecision(id: UUID) async throws
    func saveSecretEnvelope(_ envelope: CompanionSecretEnvelope) async throws
    func secretEnvelopes() async throws -> [CompanionSecretEnvelope]
    func deleteSecretEnvelope(id: UUID) async throws
    func deleteRequest(id: UUID) async throws
    func ensureRequestSubscription() async throws
}

public extension CompanionCloudServing {
    func accountIdentifier() async throws -> String {
        throw CompanionProtocolError.cloudUnavailable
    }
}

public final class CloudKitCompanionStore: CompanionCloudServing, @unchecked Sendable {
    private enum RecordType {
        static let device = "KCCompanionDeviceV1"
        static let request = "KCCompanionRequestV1"
        static let decision = "KCCompanionDecisionV1"
        static let secretEnvelope = "KCCompanionSecretEnvelopeV1"
        static let credential = "KCCompanionCredentialV1"
    }

    private enum Field {
        static let deviceName = "deviceName"
        static let signingPublicKey = "signingPublicKey"
        static let agreementPublicKey = "agreementPublicKey"
        static let createdAt = "createdAt"
        static let expiresAt = "expiresAt"
        static let status = "status"
        static let macAgreementPublicKey = "macAgreementPublicKey"
        static let macSigningPublicKey = "macSigningPublicKey"
        static let requestID = "requestID"
        static let requestDigest = "requestDigest"
        static let deviceID = "deviceID"
        static let clientName = "clientName"
        static let credentialName = "credentialName"
        static let destinationName = "destinationName"
        static let reason = "reason"
        static let action = "action"
        static let signature = "signature"
        static let secretID = "secretID"
        static let displayName = "displayName"
        static let kind = "kind"
        static let materialKind = "materialKind"
        static let ephemeralPublicKey = "ephemeralPublicKey"
        static let ciphertext = "ciphertext"
    }

    private static let requestSubscriptionID = "keycourier-companion-request-v1"
    private static let maximumRecordsPerType = 200
    private let container: CKContainer?

    public init(containerIdentifier: String = "iCloud.com.drewsdigest.KeyCourier") {
        container = Self.isEntitledForCloudKit(containerIdentifier)
            ? CKContainer(identifier: containerIdentifier)
            : nil
    }

    public func accountIdentifier() async throws -> String {
        try await requireAvailableAccount()
        let container = try requiredContainer()
        let recordID: CKRecord.ID = try await withCheckedThrowingContinuation { continuation in
            container.fetchUserRecordID { recordID, error in
                if let recordID {
                    continuation.resume(returning: recordID)
                } else {
                    continuation.resume(
                        throwing: error ?? CompanionProtocolError.cloudUnavailable
                    )
                }
            }
        }
        guard !recordID.recordName.isEmpty else {
            throw CompanionProtocolError.invalidRecord
        }
        return recordID.recordName
    }

    public func requireAvailableAccount() async throws {
        guard try await requiredContainer().accountStatus() == .available else {
            throw CompanionProtocolError.cloudUnavailable
        }
    }

    public func saveDeviceRegistration(_ registration: CompanionDeviceRegistration) async throws {
        try await requireAvailableAccount()
        try await save(records: [record(for: try registration.validated())])
    }

    public func deviceRegistration(id: UUID) async throws -> CompanionDeviceRegistration? {
        let recordID = CKRecord.ID(recordName: Self.deviceRecordName(id))
        let results = try await database().records(for: [recordID])
        guard let result = results[recordID] else { return nil }
        do {
            return try deviceRegistration(from: result.get())
        } catch let error as CKError where error.code == .unknownItem {
            return nil
        }
    }

    public func deviceRegistrations() async throws -> [CompanionDeviceRegistration] {
        try await fetchAll(recordType: RecordType.device)
            .map(deviceRegistration(from:))
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func updateDeviceRegistration(
        id: UUID,
        status: CompanionRegistrationStatus,
        macKeyAgreementPublicKey: Data?,
        macSigningPublicKey: Data?
    ) async throws {
        guard var registration = try await deviceRegistration(id: id) else {
            throw CompanionProtocolError.invalidRecord
        }
        registration.status = status
        registration.macKeyAgreementPublicKey = macKeyAgreementPublicKey
        registration.macSigningPublicKey = macSigningPublicKey
        try await saveDeviceRegistration(registration)
    }

    public func replaceRequests(_ requests: [CompanionRequestSummary]) async throws {
        guard requests.count <= Self.maximumRecordsPerType else {
            throw CompanionProtocolError.invalidRecord
        }
        for request in requests { try request.validate(at: request.createdAt) }
        let existing = try await fetchAll(recordType: RecordType.request)
        let keep = Set(requests.map { Self.requestRecordName($0.id) })
        let deletions = existing
            .map(\.recordID)
            .filter { !keep.contains($0.recordName) }
        try await modify(
            saving: try requests.map(record(for:)),
            deleting: deletions
        )
    }

    public func replaceCredentialSummaries(
        _ credentials: [CompanionCredentialSummary]
    ) async throws {
        let credentials = try credentials.map { try $0.validated() }
        guard credentials.count <= Self.maximumRecordsPerType,
              Set(credentials.map(\.secretID)).count == credentials.count else {
            throw CompanionProtocolError.invalidRecord
        }
        let existing = try await fetchAll(recordType: RecordType.credential)
        let keep = Set(credentials.map { Self.credentialRecordName($0.secretID) })
        let deletions = existing.map(\.recordID).filter { !keep.contains($0.recordName) }
        try await modify(
            saving: credentials.map(record(for:)),
            deleting: deletions
        )
    }

    public func credentialSummaries() async throws -> [CompanionCredentialSummary] {
        let summaries = try await fetchAll(recordType: RecordType.credential)
            .map(credentialSummary(from:))
        guard Set(summaries.map(\.secretID)).count == summaries.count else {
            throw CompanionProtocolError.invalidRecord
        }
        return summaries.sorted {
            $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
        }
    }

    public func purgeTransientData() async throws {
        try await requireAvailableAccount()
        let decisions = try await fetchAll(recordType: RecordType.decision)
        let envelopes = try await fetchAll(recordType: RecordType.secretEnvelope)

        for record in decisions {
            _ = try Self.uuid(from: record.recordID, prefix: "decision-")
        }
        for record in envelopes {
            _ = try Self.uuid(from: record.recordID, prefix: "secret-")
        }

        let recordIDs = (decisions + envelopes).map(\.recordID)
        guard recordIDs.count <= Self.maximumRecordsPerType * 2,
              Set(recordIDs.map(\.recordName)).count == recordIDs.count else {
            throw CompanionProtocolError.invalidRecord
        }
        guard !recordIDs.isEmpty else { return }
        try await modify(saving: [], deleting: recordIDs, atomically: true)
    }

    public func pendingRequests(at date: Date = Date()) async throws -> [CompanionRequestSummary] {
        try await fetchAll(recordType: RecordType.request)
            .map(request(from:))
            .filter { (try? $0.validate(at: date)) != nil }
            .sorted { $0.createdAt > $1.createdAt }
    }

    public func saveDecision(_ decision: CompanionDecision) async throws {
        try decision.validate(at: decision.createdAt)
        try await save(records: [try record(for: decision)])
    }

    public func decisions() async throws -> [CompanionDecision] {
        try await fetchAll(recordType: RecordType.decision)
            .map(decision(from:))
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func deleteDecision(id: UUID) async throws {
        try await delete(recordName: Self.decisionRecordName(id))
    }

    public func saveSecretEnvelope(_ envelope: CompanionSecretEnvelope) async throws {
        try envelope.validate(at: envelope.createdAt)
        try await save(records: [try record(for: envelope)])
    }

    public func secretEnvelopes() async throws -> [CompanionSecretEnvelope] {
        try await fetchAll(recordType: RecordType.secretEnvelope)
            .map(secretEnvelope(from:))
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func deleteSecretEnvelope(id: UUID) async throws {
        try await delete(recordName: Self.secretEnvelopeRecordName(id))
    }

    public func deleteRequest(id: UUID) async throws {
        try await delete(recordName: Self.requestRecordName(id))
    }

    public func ensureRequestSubscription() async throws {
        try await requireAvailableAccount()
        let database = try database()
        do {
            _ = try await database.subscription(for: Self.requestSubscriptionID)
            return
        } catch let error as CKError where error.code == .unknownItem {
            let subscription = CKQuerySubscription(
                recordType: RecordType.request,
                predicate: NSPredicate(value: true),
                subscriptionID: Self.requestSubscriptionID,
                options: [.firesOnRecordCreation]
            )
            let notification = CKSubscription.NotificationInfo()
            notification.alertBody = "A KeyCourier approval is waiting."
            notification.soundName = "default"
            notification.shouldBadge = true
            subscription.notificationInfo = notification
            let result = try await database.modifySubscriptions(
                saving: [subscription],
                deleting: []
            )
            guard let saveResult = result.saveResults[Self.requestSubscriptionID] else {
                throw CompanionProtocolError.cloudUnavailable
            }
            _ = try saveResult.get()
        }
    }

    private func fetchAll(recordType: String) async throws -> [CKRecord] {
        try await requireAvailableAccount()
        let query = CKQuery(recordType: recordType, predicate: NSPredicate(value: true))
        let result = try await database().records(
            matching: query,
            resultsLimit: Self.maximumRecordsPerType
        )
        guard result.queryCursor == nil else { throw CompanionProtocolError.invalidRecord }
        return try result.matchResults.map { try $0.1.get() }
    }

    private func save(records: [CKRecord]) async throws {
        try await modify(saving: records, deleting: [])
    }

    private func delete(recordName: String) async throws {
        try await modify(
            saving: [],
            deleting: [CKRecord.ID(recordName: recordName)]
        )
    }

    private func modify(
        saving: [CKRecord],
        deleting: [CKRecord.ID],
        atomically: Bool = false
    ) async throws {
        guard saving.count + deleting.count <= Self.maximumRecordsPerType * 2 else {
            throw CompanionProtocolError.invalidRecord
        }
        let result = try await database().modifyRecords(
            saving: saving,
            deleting: deleting,
            savePolicy: .allKeys,
            atomically: atomically
        )
        for saveResult in result.saveResults.values { _ = try saveResult.get() }
        for deleteResult in result.deleteResults.values {
            do {
                _ = try deleteResult.get()
            } catch let error as CKError where error.code == .unknownItem {
                continue
            }
        }
    }

    private func requiredContainer() throws -> CKContainer {
        guard let container else { throw CompanionProtocolError.cloudUnavailable }
        return container
    }

    private func database() throws -> CKDatabase {
        try requiredContainer().privateCloudDatabase
    }

    private static func isEntitledForCloudKit(_ containerIdentifier: String) -> Bool {
        #if os(macOS)
        guard let task = SecTaskCreateFromSelf(nil),
              let services = SecTaskCopyValueForEntitlement(
                  task,
                  "com.apple.developer.icloud-services" as CFString,
                  nil
              ) as? [String],
              services.contains("CloudKit"),
              let containers = SecTaskCopyValueForEntitlement(
                  task,
                  "com.apple.developer.icloud-container-identifiers" as CFString,
                  nil
              ) as? [String] else {
            return false
        }
        return containers.contains(containerIdentifier)
        #elseif targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }

    private func record(for registration: CompanionDeviceRegistration) -> CKRecord {
        let record = CKRecord(
            recordType: RecordType.device,
            recordID: CKRecord.ID(recordName: Self.deviceRecordName(registration.id))
        )
        record[Field.deviceName] = registration.deviceName as CKRecordValue
        record[Field.signingPublicKey] = registration.signingPublicKey as CKRecordValue
        record[Field.agreementPublicKey] = registration.keyAgreementPublicKey as CKRecordValue
        record[Field.createdAt] = registration.createdAt as CKRecordValue
        record[Field.status] = registration.status.rawValue as CKRecordValue
        record[Field.macAgreementPublicKey] = registration.macKeyAgreementPublicKey as CKRecordValue?
        record[Field.macSigningPublicKey] = registration.macSigningPublicKey as CKRecordValue?
        return record
    }

    private func deviceRegistration(from record: CKRecord) throws -> CompanionDeviceRegistration {
        try CompanionDeviceRegistration(
            id: Self.uuid(from: record.recordID, prefix: "device-"),
            deviceName: try record.string(Field.deviceName),
            signingPublicKey: try record.data(Field.signingPublicKey),
            keyAgreementPublicKey: try record.data(Field.agreementPublicKey),
            createdAt: try record.date(Field.createdAt),
            status: try CompanionRegistrationStatus(
                rawValue: record.string(Field.status)
            ).unwrapped(),
            macKeyAgreementPublicKey: record[Field.macAgreementPublicKey] as? Data,
            macSigningPublicKey: record[Field.macSigningPublicKey] as? Data
        )
    }

    private func record(for request: CompanionRequestSummary) throws -> CKRecord {
        let record = CKRecord(
            recordType: RecordType.request,
            recordID: CKRecord.ID(recordName: Self.requestRecordName(request.id))
        )
        record[Field.requestID] = request.requestID.uuidString.lowercased() as CKRecordValue
        record[Field.clientName] = request.clientName as CKRecordValue
        record[Field.credentialName] = request.credentialName as CKRecordValue
        record[Field.destinationName] = request.destinationName as CKRecordValue
        record[Field.reason] = request.reason as CKRecordValue
        record[Field.createdAt] = request.createdAt as CKRecordValue
        record[Field.expiresAt] = request.expiresAt as CKRecordValue
        record[Field.signature] = request.signature as CKRecordValue
        return record
    }

    private func request(from record: CKRecord) throws -> CompanionRequestSummary {
        let requestID = try UUID(uuidString: record.string(Field.requestID)).unwrapped()
        guard record.recordID.recordName == Self.requestRecordName(requestID) else {
            throw CompanionProtocolError.invalidRecord
        }
        return try CompanionRequestSummary(
            requestID: requestID,
            clientName: try record.string(Field.clientName),
            credentialName: try record.string(Field.credentialName),
            destinationName: try record.string(Field.destinationName),
            reason: try record.string(Field.reason),
            createdAt: try record.date(Field.createdAt),
            expiresAt: try record.date(Field.expiresAt),
            signature: try record.data(Field.signature)
        )
    }

    private func record(for decision: CompanionDecision) throws -> CKRecord {
        let record = CKRecord(
            recordType: RecordType.decision,
            recordID: CKRecord.ID(recordName: Self.decisionRecordName(decision.id))
        )
        record[Field.requestID] = decision.requestID.uuidString.lowercased() as CKRecordValue
        record[Field.requestDigest] = decision.requestDigest as CKRecordValue
        record[Field.deviceID] = decision.deviceID.uuidString.lowercased() as CKRecordValue
        record[Field.action] = decision.action.rawValue as CKRecordValue
        record[Field.createdAt] = decision.createdAt as CKRecordValue
        record[Field.expiresAt] = decision.expiresAt as CKRecordValue
        record[Field.signature] = decision.signature as CKRecordValue
        return record
    }

    private func record(for credential: CompanionCredentialSummary) -> CKRecord {
        let record = CKRecord(
            recordType: RecordType.credential,
            recordID: CKRecord.ID(recordName: Self.credentialRecordName(credential.secretID))
        )
        record[Field.secretID] = credential.secretID as CKRecordValue
        record[Field.displayName] = credential.displayName as CKRecordValue
        record[Field.kind] = credential.kind as CKRecordValue
        record[Field.materialKind] = credential.materialKind.rawValue as CKRecordValue
        return record
    }

    private func credentialSummary(from record: CKRecord) throws -> CompanionCredentialSummary {
        let secretID = try record.string(Field.secretID)
        guard record.recordID.recordName == Self.credentialRecordName(secretID) else {
            throw CompanionProtocolError.invalidRecord
        }
        let materialKindRawValue = try record.optionalString(Field.materialKind)
            ?? CompanionCredentialMaterialKind.single.rawValue
        guard let materialKind = CompanionCredentialMaterialKind(rawValue: materialKindRawValue) else {
            throw CompanionProtocolError.invalidRecord
        }
        return try CompanionCredentialSummary(
            secretID: secretID,
            displayName: record.string(Field.displayName),
            kind: record.string(Field.kind),
            materialKind: materialKind
        )
    }

    private func decision(from record: CKRecord) throws -> CompanionDecision {
        try CompanionDecision(
            id: Self.uuid(from: record.recordID, prefix: "decision-"),
            requestID: try UUID(uuidString: record.string(Field.requestID)).unwrapped(),
            requestDigest: try record.data(Field.requestDigest),
            deviceID: try UUID(uuidString: record.string(Field.deviceID)).unwrapped(),
            action: try CompanionDecisionAction(rawValue: record.string(Field.action)).unwrapped(),
            createdAt: try record.date(Field.createdAt),
            expiresAt: try record.date(Field.expiresAt),
            signature: try record.data(Field.signature)
        )
    }

    private func record(for envelope: CompanionSecretEnvelope) throws -> CKRecord {
        let record = CKRecord(
            recordType: RecordType.secretEnvelope,
            recordID: CKRecord.ID(recordName: Self.secretEnvelopeRecordName(envelope.id))
        )
        record[Field.deviceID] = envelope.deviceID.uuidString.lowercased() as CKRecordValue
        record[Field.ephemeralPublicKey] = envelope.ephemeralPublicKey as CKRecordValue
        record[Field.ciphertext] = envelope.ciphertext as CKRecordValue
        record[Field.createdAt] = envelope.createdAt as CKRecordValue
        record[Field.expiresAt] = envelope.expiresAt as CKRecordValue
        record[Field.signature] = envelope.signature as CKRecordValue
        return record
    }

    private func secretEnvelope(from record: CKRecord) throws -> CompanionSecretEnvelope {
        try CompanionSecretEnvelope(
            id: Self.uuid(from: record.recordID, prefix: "secret-"),
            deviceID: try UUID(uuidString: record.string(Field.deviceID)).unwrapped(),
            ephemeralPublicKey: try record.data(Field.ephemeralPublicKey),
            ciphertext: try record.data(Field.ciphertext),
            createdAt: try record.date(Field.createdAt),
            expiresAt: try record.date(Field.expiresAt),
            signature: try record.data(Field.signature)
        )
    }

    private static func deviceRecordName(_ id: UUID) -> String { "device-\(id.uuidString.lowercased())" }
    private static func requestRecordName(_ id: UUID) -> String { "request-\(id.uuidString.lowercased())" }
    private static func decisionRecordName(_ id: UUID) -> String { "decision-\(id.uuidString.lowercased())" }
    private static func secretEnvelopeRecordName(_ id: UUID) -> String { "secret-\(id.uuidString.lowercased())" }
    private static func credentialRecordName(_ secretID: String) -> String { "credential-\(secretID)" }

    private static func uuid(from recordID: CKRecord.ID, prefix: String) throws -> UUID {
        guard recordID.recordName.hasPrefix(prefix),
              let id = UUID(uuidString: String(recordID.recordName.dropFirst(prefix.count))) else {
            throw CompanionProtocolError.invalidRecord
        }
        return id
    }
}

private extension CKRecord {
    func optionalString(_ key: String) throws -> String? {
        guard let value = self[key] else { return nil }
        guard let value = value as? String else { throw CompanionProtocolError.invalidRecord }
        return value
    }

    func string(_ key: String) throws -> String {
        guard let value = self[key] as? String else { throw CompanionProtocolError.invalidRecord }
        return value
    }

    func data(_ key: String) throws -> Data {
        guard let value = self[key] as? Data else { throw CompanionProtocolError.invalidRecord }
        return value
    }

    func date(_ key: String) throws -> Date {
        guard let value = self[key] as? Date else { throw CompanionProtocolError.invalidRecord }
        return value
    }
}

private extension Optional {
    func unwrapped() throws -> Wrapped {
        guard let self else { throw CompanionProtocolError.invalidRecord }
        return self
    }
}
