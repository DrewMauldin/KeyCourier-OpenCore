import Foundation
import KeyCourierCore

private struct PendingStatus: Encodable {
    let requestID: UUID
    let status = "pending"
}

private struct SecretIdentifier: Encodable {
    let secretID: String
}

private struct ConsumerIdentifier: Encodable {
    let consumerID: String
    let targetID: String
}

private struct DoctorCheck: Encodable {
    let code: String
    let status: String
    let remediation: String?
}

private struct DoctorReport: Encodable {
    let status: String
    let checks: [DoctorCheck]
}

private func printJSON<Value: Encodable>(_ value: Value) throws {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys]
    FileHandle.standardOutput.write(try encoder.encode(value))
    FileHandle.standardOutput.write(Data("\n".utf8))
}

private func wakeApp() {
    let process = Process()
    process.executableURL = URL(filePath: "/usr/bin/open")
    process.arguments = ["-b", "com.drewsdigest.KeyCourier"]
    try? process.run()
}

private func privateDirectoryCheck(_ url: URL, code: String) -> DoctorCheck {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    let permissions = attributes?[.posixPermissions] as? NSNumber
    let isDirectory = (attributes?[.type] as? FileAttributeType) == .typeDirectory
    if isDirectory, permissions?.intValue == 0o700 {
        return DoctorCheck(code: code, status: "ready", remediation: nil)
    }
    return DoctorCheck(
        code: code,
        status: "failed",
        remediation: "Open KeyCourier once, then run doctor again."
    )
}

private func hostCheck(alias: String) -> DoctorCheck {
    let process = Process()
    process.executableURL = URL(filePath: "/usr/bin/ssh")
    process.arguments = [
        "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=yes", alias, "/usr/bin/true"
    ]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return DoctorCheck(
            code: "host.\(alias).unavailable",
            status: "failed",
            remediation: "Check the approved SSH alias and host connection."
        )
    }
    guard process.terminationStatus == 0 else {
        return DoctorCheck(
            code: "host.\(alias).unavailable",
            status: "failed",
            remediation: "Check the approved SSH alias and host connection."
        )
    }
    return DoctorCheck(code: "host.\(alias).reachable", status: "ready", remediation: nil)
}

private func doctor(directories: AppDirectories) -> DoctorReport {
    try? FileManager.default.createDirectory(
        at: directories.inbox,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )

    var checks = [
        DoctorCheck(
            code: "app.installed",
            status: FileManager.default.fileExists(atPath: "/Applications/KeyCourier.app") ? "ready" : "failed",
            remediation: FileManager.default.fileExists(atPath: "/Applications/KeyCourier.app")
                ? nil
                : "Run the reviewed KeyCourier installer."
        ),
        privateDirectoryCheck(directories.root, code: "storage.root.private"),
        privateDirectoryCheck(directories.inbox, code: "storage.inbox.private")
    ]

    let agePath = FileManager.default.homeDirectoryForCurrentUser
        .appending(path: ".local/bin/age").path
    checks.append(DoctorCheck(
        code: "age.installed",
        status: FileManager.default.isExecutableFile(atPath: agePath) ? "ready" : "failed",
        remediation: FileManager.default.isExecutableFile(atPath: agePath)
            ? nil
            : "Run the reviewed host integration installer."
    ))

    do {
        let profiles = try FileRemoteAgeProfileStore(root: directories.metadata).profiles()
        if profiles.isEmpty {
            checks.append(DoctorCheck(
                code: "profiles.missing",
                status: "failed",
                remediation: "Run the reviewed host integration installer."
            ))
        } else {
            checks.append(DoctorCheck(code: "profiles.loaded", status: "ready", remediation: nil))
            checks.append(contentsOf: profiles.map(\.sshAlias).sorted().map(hostCheck))
        }
    } catch {
        checks.append(DoctorCheck(
            code: "profiles.invalid",
            status: "failed",
            remediation: "Reinstall the reviewed public host profiles."
        ))
    }

    return DoctorReport(
        status: checks.allSatisfy { $0.status == "ready" } ? "ready" : "attention",
        checks: checks
    )
}

do {
    let command = try AgentCommand.parse(arguments: Array(CommandLine.arguments.dropFirst()))
    let directories = AppDirectories.standard
    switch command {
    case .request(let request):
        try FileRequestInbox(root: directories.inbox).submit(request)
        try printJSON(PendingStatus(requestID: request.id))
        wakeApp()
    case .status(let requestID):
        if let receipt = try FileReceiptStore(root: directories.receipts).receipt(for: requestID) {
            try printJSON(receipt)
        } else {
            try printJSON(PendingStatus(requestID: requestID))
        }
    case .secrets:
        let records = try FileMetadataStore(root: directories.metadata).secrets()
            .map { SecretIdentifier(secretID: $0.id.rawValue) }
        try printJSON(records)
    case .consumers:
        let records = try FileMetadataStore(root: directories.metadata).consumers()
            .map {
                ConsumerIdentifier(
                    consumerID: $0.id.rawValue,
                    targetID: $0.targetID.rawValue
                )
            }
        try printJSON(records)
    case .doctor:
        try printJSON(doctor(directories: directories))
    }
} catch {
    FileHandle.standardError.write(Data("keycourier: \(error.localizedDescription)\n".utf8))
    exit(64)
}
