import Foundation
import Security

public enum TelegramApprovalAction: String, Codable, Equatable, Sendable {
    case approve = "a"
    case deny = "d"
}

public struct TelegramConfiguration: Codable, Equatable, Sendable {
    public let chatID: Int64
    public let userID: Int64
    public let botUsername: String
    public var lastUpdateID: Int64
    public var isEnabled: Bool

    public init(
        chatID: Int64,
        userID: Int64,
        botUsername: String,
        lastUpdateID: Int64,
        isEnabled: Bool = true
    ) throws {
        let username = botUsername.trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
        guard chatID != 0,
              userID > 0,
              !username.isEmpty,
              username.count <= 64,
              username.unicodeScalars.allSatisfy(allowed.contains) else {
            throw KeyCourierError.telegramNotConfigured
        }
        self.chatID = chatID
        self.userID = userID
        self.botUsername = username
        self.lastUpdateID = lastUpdateID
        self.isEnabled = isEnabled
    }
}

public struct TelegramApprovalRecord: Codable, Equatable, Identifiable, Sendable {
    public enum State: String, Codable, Sendable {
        case prepared
        case sent
        case consumed
    }

    public var id: UUID { requestID }
    public let requestID: UUID
    public let nonce: String
    public let expiresAt: Date
    public var state: State
    public var sendAttempts: Int

    public init(
        requestID: UUID,
        nonce: String,
        expiresAt: Date,
        state: State = .prepared,
        sendAttempts: Int = 0
    ) throws {
        guard expiresAt > Date().addingTimeInterval(-24 * 60 * 60),
              nonce.count == 32,
              nonce.allSatisfy({ $0.isHexDigit }),
              (0...3).contains(sendAttempts) else {
            throw KeyCourierError.approvalInvalid
        }
        self.requestID = requestID
        self.nonce = nonce.lowercased()
        self.expiresAt = expiresAt
        self.state = state
        self.sendAttempts = sendAttempts
    }

    public var approveCallbackData: String { "kc:a:\(nonce)" }
    public var denyCallbackData: String { "kc:d:\(nonce)" }
}

public struct TelegramApprovalState: Codable, Equatable, Sendable {
    public var configuration: TelegramConfiguration?
    public var approvals: [TelegramApprovalRecord]

    public init(configuration: TelegramConfiguration? = nil, approvals: [TelegramApprovalRecord] = []) {
        self.configuration = configuration
        self.approvals = approvals
    }
}

public struct FileTelegramApprovalStore: Sendable {
    private static let maximumBytes = 256 * 1024
    private let root: URL
    private var stateURL: URL { root.appending(path: "telegram.json") }

    public init(root: URL) {
        self.root = root
    }

    public func state() throws -> TelegramApprovalState {
        try SecureFileSystem.ensurePrivateDirectory(root)
        guard try SecureFileSystem.fileExists(stateURL) else { return TelegramApprovalState() }
        let data = try SecureFileSystem.readRegularFile(stateURL, maximumBytes: Self.maximumBytes)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try validated(decoder.decode(TelegramApprovalState.self, from: data))
    }

    public func save(_ state: TelegramApprovalState) throws {
        let state = try validated(state)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFileSystem.writeAtomically(encoder.encode(state), to: stateURL)
    }

    public func saveConfiguration(_ configuration: TelegramConfiguration?) throws {
        var current = try state()
        current.configuration = configuration
        if configuration == nil { current.approvals.removeAll() }
        try save(current)
    }

    public func setLastUpdateID(_ updateID: Int64) throws {
        var current = try state()
        guard let configuration = current.configuration else {
            throw KeyCourierError.telegramNotConfigured
        }
        current.configuration = try TelegramConfiguration(
            chatID: configuration.chatID,
            userID: configuration.userID,
            botUsername: configuration.botUsername,
            lastUpdateID: max(configuration.lastUpdateID, updateID),
            isEnabled: configuration.isEnabled
        )
        try save(current)
    }

    public func preparedApproval(for request: SecretRequest) throws -> TelegramApprovalRecord {
        var current = try state()
        if let existing = current.approvals.first(where: { $0.requestID == request.id }) {
            return existing
        }
        let record = try TelegramApprovalRecord(
            requestID: request.id,
            nonce: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            expiresAt: request.expiresAt
        )
        current.approvals.append(record)
        try save(current)
        return record
    }

    public func markSent(requestID: UUID) throws {
        try update(requestID: requestID) { record in
            guard record.state != .consumed else { throw KeyCourierError.approvalInvalid }
            record.state = .sent
            record.sendAttempts += 1
        }
    }

    public func markSendFailed(requestID: UUID) throws {
        try update(requestID: requestID) { record in
            guard record.state == .prepared else { return }
            record.sendAttempts += 1
        }
    }

    public func consume(
        nonce: String,
        action: TelegramApprovalAction,
        chatID: Int64,
        userID: Int64,
        at date: Date = Date()
    ) throws -> (UUID, TelegramApprovalAction) {
        var current = try state()
        guard let configuration = current.configuration,
              configuration.isEnabled,
              configuration.chatID == chatID,
              configuration.userID == userID,
              let index = current.approvals.firstIndex(where: {
                  $0.nonce == nonce.lowercased() && $0.state == .sent
              }),
              current.approvals[index].expiresAt >= date else {
            throw KeyCourierError.approvalInvalid
        }
        let requestID = current.approvals[index].requestID
        current.approvals[index].state = .consumed
        try save(current)
        return (requestID, action)
    }

    public func removeFinished(requestIDs: Set<UUID>, at date: Date = Date()) throws {
        var current = try state()
        current.approvals.removeAll {
            requestIDs.contains($0.requestID) || $0.expiresAt < date
        }
        try save(current)
    }

    private func update(requestID: UUID, mutation: (inout TelegramApprovalRecord) throws -> Void) throws {
        var current = try state()
        guard let index = current.approvals.firstIndex(where: { $0.requestID == requestID }) else {
            throw KeyCourierError.approvalInvalid
        }
        try mutation(&current.approvals[index])
        try save(current)
    }

    private func validated(_ state: TelegramApprovalState) throws -> TelegramApprovalState {
        guard state.approvals.count <= 200,
              Set(state.approvals.map(\.requestID)).count == state.approvals.count,
              Set(state.approvals.map(\.nonce)).count == state.approvals.count,
              state.approvals.allSatisfy({ record in
                  (try? TelegramApprovalRecord(
                      requestID: record.requestID,
                      nonce: record.nonce,
                      expiresAt: record.expiresAt,
                      state: record.state,
                      sendAttempts: record.sendAttempts
                  )) != nil
              }) else {
            throw KeyCourierError.approvalInvalid
        }
        if let configuration = state.configuration {
            _ = try TelegramConfiguration(
                chatID: configuration.chatID,
                userID: configuration.userID,
                botUsername: configuration.botUsername,
                lastUpdateID: configuration.lastUpdateID,
                isEnabled: configuration.isEnabled
            )
        }
        return state
    }
}

public struct TelegramBotTokenStore: Sendable {
    private static let service = "com.drewsdigest.KeyCourier.integrations"
    private static let account = "telegram-bot"

    public init() {}

    public func save(_ token: String) throws {
        let token = try Self.validatedToken(token)
        let data = Data(token.utf8)
        var query = Self.baseQuery
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeyCourierError.keychainFailure(status) }
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeyCourierError.keychainFailure(addStatus) }
    }

    public func read() throws -> String? {
        var query = Self.baseQuery
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            throw KeyCourierError.keychainFailure(status)
        }
        return try Self.validatedToken(token)
    }

    public func delete() throws {
        let status = SecItemDelete(Self.baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyCourierError.keychainFailure(status)
        }
    }

    public static func validatedToken(_ token: String) throws -> String {
        let token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = token.split(separator: ":", omittingEmptySubsequences: false)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        guard parts.count == 2,
              parts[0].count >= 6,
              parts[0].allSatisfy(\.isNumber),
              parts[1].count >= 20,
              parts[1].count <= 96,
              parts[1].unicodeScalars.allSatisfy(allowed.contains) else {
            throw KeyCourierError.telegramNotConfigured
        }
        return token
    }

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

public struct TelegramBotIdentity: Equatable, Sendable {
    public let username: String
}

public struct TelegramPairingResult: Equatable, Sendable {
    public let chatID: Int64
    public let userID: Int64
    public let updateID: Int64
}

public struct TelegramApprovalEvent: Equatable, Sendable {
    public let updateID: Int64
    public let callbackQueryID: String
    public let chatID: Int64
    public let userID: Int64
    public let action: TelegramApprovalAction
    public let nonce: String
}

public struct TelegramApprovalBatch: Equatable, Sendable {
    public let latestUpdateID: Int64
    public let events: [TelegramApprovalEvent]

    public init(latestUpdateID: Int64, events: [TelegramApprovalEvent]) {
        self.latestUpdateID = latestUpdateID
        self.events = events
    }
}

public protocol TelegramBotServing: Sendable {
    func identity(token: String) async throws -> TelegramBotIdentity
    func findPairing(token: String, code: String, after updateID: Int64) async throws -> TelegramPairingResult?
    func sendApproval(
        token: String,
        chatID: Int64,
        title: String,
        destination: String,
        client: String,
        expiresAt: Date,
        record: TelegramApprovalRecord
    ) async throws
    func approvalEvents(token: String, after updateID: Int64) async throws -> TelegramApprovalBatch
    func answerCallback(token: String, callbackQueryID: String, text: String) async
}

public struct TelegramBotAPI: TelegramBotServing, Sendable {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func identity(token: String) async throws -> TelegramBotIdentity {
        let response: APIResponse<BotUser> = try await request(token: token, method: "getMe", body: EmptyBody())
        guard response.ok, let username = response.result?.username, !username.isEmpty else {
            throw KeyCourierError.telegramRequestFailed
        }
        return TelegramBotIdentity(username: username)
    }

    public func findPairing(
        token: String,
        code: String,
        after updateID: Int64
    ) async throws -> TelegramPairingResult? {
        let updates = try await updates(token: token, after: updateID)
        let expected = "/pair \(code)"
        return updates.compactMap { update in
            guard update.message?.text == expected,
                  let chatID = update.message?.chat.id,
                  let userID = update.message?.from?.id,
                  update.message?.chat.type == "private" else { return nil }
            return TelegramPairingResult(chatID: chatID, userID: userID, updateID: update.updateID)
        }.last
    }

    public func sendApproval(
        token: String,
        chatID: Int64,
        title: String,
        destination: String,
        client: String,
        expiresAt: Date,
        record: TelegramApprovalRecord
    ) async throws {
        let safeTitle = String(title.prefix(80))
        let safeDestination = String(destination.prefix(80))
        let safeClient = String(client.prefix(32))
        let text = "KeyCourier approval\n\n\(safeTitle)\nDestination: \(safeDestination)\nRequested by: \(safeClient)\nExpires: \(expiresAt.formatted(date: .abbreviated, time: .shortened))\n\nNo secret value is included."
        let buttons = InlineKeyboardMarkup(inlineKeyboard: [[
            InlineKeyboardButton(text: "Approve", callbackData: record.approveCallbackData),
            InlineKeyboardButton(text: "Decline", callbackData: record.denyCallbackData),
        ]])
        let body = SendMessageBody(chatID: chatID, text: text, replyMarkup: buttons)
        let response: APIResponse<Message> = try await request(token: token, method: "sendMessage", body: body)
        guard response.ok, response.result != nil else { throw KeyCourierError.telegramRequestFailed }
    }

    public func approvalEvents(token: String, after updateID: Int64) async throws -> TelegramApprovalBatch {
        let updates = try await updates(token: token, after: updateID)
        let events: [TelegramApprovalEvent] = updates.compactMap { update in
            guard let callback = update.callbackQuery,
                  let data = callback.data,
                  let chatID = callback.message?.chat.id else { return nil }
            let parts = data.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 3,
                  parts[0] == "kc",
                  let action = TelegramApprovalAction(rawValue: String(parts[1])),
                  parts[2].count == 32,
                  parts[2].allSatisfy({ $0.isHexDigit }) else { return nil }
            return TelegramApprovalEvent(
                updateID: update.updateID,
                callbackQueryID: callback.id,
                chatID: chatID,
                userID: callback.from.id,
                action: action,
                nonce: String(parts[2]).lowercased()
            )
        }
        return TelegramApprovalBatch(
            latestUpdateID: updates.map(\.updateID).max() ?? updateID,
            events: events
        )
    }

    public func answerCallback(token: String, callbackQueryID: String, text: String) async {
        let body = AnswerCallbackBody(callbackQueryID: callbackQueryID, text: String(text.prefix(120)))
        let _: APIResponse<Bool>? = try? await request(token: token, method: "answerCallbackQuery", body: body)
    }

    private func updates(token: String, after updateID: Int64) async throws -> [Update] {
        let body = GetUpdatesBody(offset: afterUpdateID(afterID: updateID), limit: 50, timeout: 0)
        let response: APIResponse<[Update]> = try await request(token: token, method: "getUpdates", body: body)
        guard response.ok else { throw KeyCourierError.telegramRequestFailed }
        return response.result ?? []
    }

    private func request<Body: Encodable, Result: Decodable>(
        token: String,
        method: String,
        body: Body
    ) async throws -> APIResponse<Result> {
        let token = try TelegramBotTokenStore.validatedToken(token)
        guard let url = URL(string: "https://api.telegram.org/bot\(token)/\(method)") else {
            throw KeyCourierError.telegramRequestFailed
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              data.count <= 512 * 1024 else {
            throw KeyCourierError.telegramRequestFailed
        }
        return try JSONDecoder().decode(APIResponse<Result>.self, from: data)
    }

    private func afterUpdateID(afterID: Int64) -> Int64 {
        afterID == Int64.max ? afterID : afterID + 1
    }
}

private struct APIResponse<Result: Decodable>: Decodable {
    let ok: Bool
    let result: Result?
}

private struct EmptyBody: Encodable {}

private struct BotUser: Decodable {
    let username: String?
}

private struct GetUpdatesBody: Encodable {
    let offset: Int64
    let limit: Int
    let timeout: Int
}

private struct SendMessageBody: Encodable {
    let chatID: Int64
    let text: String
    let replyMarkup: InlineKeyboardMarkup

    enum CodingKeys: String, CodingKey {
        case chatID = "chat_id"
        case text
        case replyMarkup = "reply_markup"
    }
}

private struct AnswerCallbackBody: Encodable {
    let callbackQueryID: String
    let text: String

    enum CodingKeys: String, CodingKey {
        case callbackQueryID = "callback_query_id"
        case text
    }
}

private struct InlineKeyboardMarkup: Encodable {
    let inlineKeyboard: [[InlineKeyboardButton]]

    enum CodingKeys: String, CodingKey {
        case inlineKeyboard = "inline_keyboard"
    }
}

private struct InlineKeyboardButton: Encodable {
    let text: String
    let callbackData: String

    enum CodingKeys: String, CodingKey {
        case text
        case callbackData = "callback_data"
    }
}

private struct Update: Decodable {
    let updateID: Int64
    let message: Message?
    let callbackQuery: CallbackQuery?

    enum CodingKeys: String, CodingKey {
        case updateID = "update_id"
        case message
        case callbackQuery = "callback_query"
    }
}

private struct Message: Decodable {
    let chat: Chat
    let from: TelegramUser?
    let text: String?
}

private struct CallbackQuery: Decodable {
    let id: String
    let from: TelegramUser
    let message: Message?
    let data: String?
}

private struct Chat: Decodable {
    let id: Int64
    let type: String?
}

private struct TelegramUser: Decodable {
    let id: Int64
}
