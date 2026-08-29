import Darwin
import Foundation

enum SecureFileSystem {
    enum DirectoryPolicy {
        case managedPrivate
        case existingOwnerControlled
    }

    private struct ParsedPath {
        let isAbsolute: Bool
        let components: [String]

        var fileName: String {
            components[components.count - 1]
        }

        var parentComponents: [String] {
            Array(components.dropLast())
        }
    }

    static func ensurePrivateDirectory(_ url: URL, trustedAnchor: URL? = nil) throws {
        let path = try parse(url)
        let descriptor = try openDirectoryChain(
            path.components,
            isAbsolute: path.isAbsolute,
            createIntermediate: true,
            requireCurrentOwnerForFinal: true,
            makeFinalPrivate: true,
            trustedAnchor: trustedAnchor
        )
        defer { close(descriptor) }
        try syncDirectory(descriptor)
    }

    static func readRegularFile(
        _ url: URL,
        maximumBytes: Int,
        trustedAnchor: URL? = nil
    ) throws -> Data {
        guard maximumBytes >= 0 else { throw KeyCourierError.unsafeFile }
        let path = try parse(url)
        let parent = try openParentDirectory(
            path,
            createIntermediate: false,
            makePrivate: false,
            trustedAnchor: trustedAnchor
        )
        defer { close(parent) }

        let descriptor = try openExistingFile(parent, name: path.fileName)
        defer { close(descriptor) }

        let initialInfo = try regularFileInfo(descriptor)
        guard initialInfo.st_size <= off_t(maximumBytes) else {
            throw KeyCourierError.unsafeFile
        }

        var data = Data(count: Int(initialInfo.st_size))
        try data.withUnsafeMutableBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = read(
                    descriptor,
                    buffer.baseAddress?.advanced(by: offset),
                    buffer.count - offset
                )
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    throw POSIXError(.EIO)
                }
            }
        }

        let finalInfo = try regularFileInfo(descriptor)
        guard finalInfo.st_dev == initialInfo.st_dev,
              finalInfo.st_ino == initialInfo.st_ino,
              finalInfo.st_size == initialInfo.st_size else {
            throw KeyCourierError.unsafeFile
        }
        return data
    }

    static func writeAtomically(
        _ data: Data,
        to url: URL,
        directoryPolicy: DirectoryPolicy = .managedPrivate,
        trustedAnchor: URL? = nil
    ) throws {
        try writeAtomically(
            data,
            to: url,
            directoryPolicy: directoryPolicy,
            replaceExisting: true,
            trustedAnchor: trustedAnchor
        )
    }

    static func writeAtomicallyIfAbsent(
        _ data: Data,
        to url: URL,
        directoryPolicy: DirectoryPolicy = .managedPrivate,
        trustedAnchor: URL? = nil
    ) throws {
        try writeAtomically(
            data,
            to: url,
            directoryPolicy: directoryPolicy,
            replaceExisting: false,
            trustedAnchor: trustedAnchor
        )
    }

    private static func writeAtomically(
        _ data: Data,
        to url: URL,
        directoryPolicy: DirectoryPolicy,
        replaceExisting: Bool,
        trustedAnchor: URL?
    ) throws {
        let path = try parse(url)
        let createIntermediate: Bool
        let makePrivate: Bool
        switch directoryPolicy {
        case .managedPrivate:
            createIntermediate = true
            makePrivate = true
        case .existingOwnerControlled:
            createIntermediate = false
            makePrivate = false
        }
        let parent = try openParentDirectory(
            path,
            createIntermediate: createIntermediate,
            makePrivate: makePrivate,
            trustedAnchor: trustedAnchor
        )
        defer { close(parent) }

        try validateExistingDestination(parent, name: path.fileName)

        let temporaryName = ".keycourier-\(UUID().uuidString).tmp"
        let descriptor = temporaryName.withCString {
            openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600
            )
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var descriptorToClose = descriptor
        var shouldRemoveTemporary = true
        defer {
            if descriptorToClose >= 0 {
                close(descriptorToClose)
            }
            if shouldRemoveTemporary {
                _ = temporaryName.withCString { unlinkat(parent, $0, 0) }
            }
        }

        var temporaryInfo = stat()
        guard fstat(descriptor, &temporaryInfo) == 0,
              (temporaryInfo.st_mode & S_IFMT) == S_IFREG,
              temporaryInfo.st_uid == getuid(),
              temporaryInfo.st_nlink == 1 else {
            throw KeyCourierError.unsafeFile
        }

        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let result = write(
                    descriptor,
                    buffer.baseAddress?.advanced(by: offset),
                    buffer.count - offset
                )
                if result < 0, errno == EINTR {
                    continue
                }
                guard result > 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                offset += result
            }
        }

        guard fchmod(descriptor, 0o600) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try syncFile(descriptor)

        let renameResult = temporaryName.withCString { temporaryPointer in
            path.fileName.withCString { destinationPointer in
                if replaceExisting {
                    renameat(parent, temporaryPointer, parent, destinationPointer)
                } else {
                    renameatx_np(
                        parent,
                        temporaryPointer,
                        parent,
                        destinationPointer,
                        UInt32(RENAME_EXCL)
                    )
                }
            }
        }
        guard renameResult == 0 else {
            let code = errno
            if !replaceExisting, code == EEXIST {
                throw KeyCourierError.replayedRequest
            }
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
        shouldRemoveTemporary = false

        let closeResult = close(descriptor)
        descriptorToClose = -1
        guard closeResult == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try syncDirectory(parent)
        try validateExistingDestination(parent, name: path.fileName)
    }

    static func fileExists(_ url: URL, trustedAnchor: URL? = nil) throws -> Bool {
        let path = try parse(url)
        let parent = try openParentDirectory(
            path,
            createIntermediate: false,
            makePrivate: false,
            trustedAnchor: trustedAnchor
        )
        defer { close(parent) }

        var info = stat()
        let result = path.fileName.withCString {
            fstatat(parent, $0, &info, AT_SYMLINK_NOFOLLOW)
        }
        if result == 0 {
            try validateRegularFile(info)
            return true
        }
        guard errno == ENOENT else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return false
    }

    static func removeRegularFile(_ url: URL, trustedAnchor: URL? = nil) throws {
        let path = try parse(url)
        let parent = try openParentDirectory(
            path,
            createIntermediate: false,
            makePrivate: false,
            trustedAnchor: trustedAnchor
        )
        defer { close(parent) }

        var info = stat()
        let status = path.fileName.withCString {
            fstatat(parent, $0, &info, AT_SYMLINK_NOFOLLOW)
        }
        if status != 0 {
            guard errno == ENOENT else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            return
        }
        try validateRegularFile(info)
        guard path.fileName.withCString({ unlinkat(parent, $0, 0) }) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try syncDirectory(parent)
    }

    static func removeEntryWithoutFollowing(_ url: URL, trustedAnchor: URL? = nil) throws {
        let path = try parse(url)
        let parent = try openParentDirectory(
            path,
            createIntermediate: false,
            makePrivate: false,
            trustedAnchor: trustedAnchor
        )
        defer { close(parent) }

        var info = stat()
        let status = path.fileName.withCString {
            fstatat(parent, $0, &info, AT_SYMLINK_NOFOLLOW)
        }
        if status != 0 {
            guard errno == ENOENT else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            return
        }
        guard (info.st_mode & S_IFMT) != S_IFDIR,
              info.st_uid == getuid() else {
            throw KeyCourierError.unsafeFile
        }
        guard path.fileName.withCString({ unlinkat(parent, $0, 0) }) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try syncDirectory(parent)
    }

    static func createExclusiveMarker(_ url: URL, trustedAnchor: URL? = nil) throws {
        let path = try parse(url)
        let parent = try openParentDirectory(
            path,
            createIntermediate: false,
            makePrivate: false,
            trustedAnchor: trustedAnchor
        )
        defer { close(parent) }

        let descriptor = path.fileName.withCString {
            openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600
            )
        }
        guard descriptor >= 0 else {
            if errno == EEXIST {
                throw KeyCourierError.replayedRequest
            }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var descriptorToClose = descriptor
        var shouldRemove = true
        defer {
            if descriptorToClose >= 0 {
                close(descriptorToClose)
            }
            if shouldRemove {
                _ = path.fileName.withCString { unlinkat(parent, $0, 0) }
            }
        }

        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try validateRegularFile(info)
        guard fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let closeResult = close(descriptor)
        descriptorToClose = -1
        guard closeResult == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try syncDirectory(parent)
        shouldRemove = false
    }

    private static func parse(_ url: URL) throws -> ParsedPath {
        guard url.isFileURL else { throw KeyCourierError.unsafeFile }
        let rawPath = url.path
        guard !rawPath.isEmpty, !rawPath.utf8.contains(0) else {
            throw KeyCourierError.unsafeFile
        }

        let isAbsolute = rawPath.hasPrefix("/")
        var components = rawPath
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
            .filter { $0 != "." }
        guard !components.isEmpty else { throw KeyCourierError.unsafeFile }
        guard components.allSatisfy({ !$0.isEmpty && !$0.contains("\0") && $0 != ".." }) else {
            throw KeyCourierError.unsafeFile
        }

        // macOS exposes /var and /tmp as stable system aliases. Resolve only
        // those aliases lexically so every component opened below is a real
        // directory, while arbitrary user-controlled symlinks are rejected.
        if isAbsolute, components.first == "var" {
            components[0] = "private"
            components.insert("var", at: 1)
        } else if isAbsolute, components.first == "tmp" {
            components[0] = "private"
            components.insert("tmp", at: 1)
        }

        return ParsedPath(isAbsolute: isAbsolute, components: components)
    }

    private static func openParentDirectory(
        _ path: ParsedPath,
        createIntermediate: Bool,
        makePrivate: Bool,
        trustedAnchor: URL?
    ) throws -> Int32 {
        guard !path.parentComponents.isEmpty else {
            throw KeyCourierError.unsafeFile
        }
        return try openDirectoryChain(
            path.parentComponents,
            isAbsolute: path.isAbsolute,
            createIntermediate: createIntermediate,
            requireCurrentOwnerForFinal: true,
            makeFinalPrivate: makePrivate,
            trustedAnchor: trustedAnchor
        )
    }

    private static func openDirectoryChain(
        _ components: [String],
        isAbsolute: Bool,
        createIntermediate: Bool,
        requireCurrentOwnerForFinal: Bool,
        makeFinalPrivate: Bool,
        trustedAnchor: URL?
    ) throws -> Int32 {
        let anchorPath = try trustedAnchor.map(parse)
        var remainingComponents = components
        let rootDescriptor: Int32
        if let anchorPath {
            guard anchorPath.isAbsolute,
                  isAbsolute,
                  components.starts(with: anchorPath.components) else {
                throw KeyCourierError.unsafeFile
            }
            remainingComponents.removeFirst(anchorPath.components.count)
            rootDescriptor = try openTrustedAnchor(anchorPath)
        } else {
            let rootPath = isAbsolute ? "/" : "."
            let descriptor = rootPath.withCString {
                open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            }
            guard descriptor >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            rootDescriptor = descriptor
        }

        var current = rootDescriptor
        do {
            if remainingComponents.isEmpty {
                try validateDirectory(current, requireCurrentOwner: requireCurrentOwnerForFinal)
                if makeFinalPrivate {
                    guard fchmod(current, 0o700) == 0 else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                }
                return current
            }

            for (index, component) in remainingComponents.enumerated() {
                let isFinal = index == remainingComponents.count - 1
                let child = try openDirectoryChild(current, name: component, create: createIntermediate)
                do {
                    try validateDirectory(child, requireCurrentOwner: isFinal && requireCurrentOwnerForFinal)
                    if isFinal, makeFinalPrivate {
                        guard fchmod(child, 0o700) == 0 else {
                            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                        }
                        try syncDirectory(child)
                    }
                } catch {
                    close(child)
                    throw error
                }
                close(current)
                current = child
            }
            return current
        } catch {
            close(current)
            throw error
        }
    }

    private static func openTrustedAnchor(_ path: ParsedPath) throws -> Int32 {
        guard path.isAbsolute else { throw KeyCourierError.unsafeFile }
        let rootDescriptor = "/".withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard rootDescriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var current = rootDescriptor
        do {
            for component in path.components {
                let child = try openDirectoryChild(current, name: component, create: false)
                do {
                    try validateDirectory(child, requireCurrentOwner: false)
                } catch {
                    close(child)
                    throw error
                }
                close(current)
                current = child
            }
            try validateDirectory(current, requireCurrentOwner: true)
            return current
        } catch {
            close(current)
            throw error
        }
    }

    private static func openDirectoryChild(_ parent: Int32, name: String, create: Bool) throws -> Int32 {
        let flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        var descriptor = name.withCString { openat(parent, $0, flags) }
        if descriptor < 0, create, errno == ENOENT {
            let result = name.withCString { mkdirat(parent, $0, 0o700) }
            if result < 0, errno != EEXIST {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            if result == 0 {
                try syncDirectory(parent)
            }
            descriptor = name.withCString { openat(parent, $0, flags) }
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return descriptor
    }

    private static func openExistingFile(_ parent: Int32, name: String) throws -> Int32 {
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        do {
            _ = try regularFileInfo(descriptor)
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private static func validateDirectory(_ descriptor: Int32, requireCurrentOwner: Bool) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            throw KeyCourierError.unsafeFile
        }

        let owner = info.st_uid
        let currentUser = getuid()
        guard owner == currentUser || owner == 0 else {
            throw KeyCourierError.unsafeFile
        }

        let mode = info.st_mode & 0o7777
        let writableByOtherUsers = mode & 0o0022
        if writableByOtherUsers != 0 {
            guard owner == 0, (mode & 0o1000) != 0 else {
                throw KeyCourierError.unsafeFile
            }
        }
        if requireCurrentOwner, owner != currentUser {
            throw KeyCourierError.unsafeFile
        }
    }

    private static func regularFileInfo(_ descriptor: Int32) throws -> stat {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try validateRegularFile(info)
        return info
    }

    private static func validateRegularFile(_ info: stat) throws {
        guard (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              info.st_nlink == 1,
              info.st_size >= 0,
              (info.st_mode & 0o0022) == 0 else {
            throw KeyCourierError.unsafeFile
        }
    }

    private static func validateExistingDestination(_ parent: Int32, name: String) throws {
        var info = stat()
        let result = name.withCString {
            fstatat(parent, $0, &info, AT_SYMLINK_NOFOLLOW)
        }
        if result == 0 {
            try validateRegularFile(info)
            return
        }
        guard errno == ENOENT else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private static func syncFile(_ descriptor: Int32) throws {
        guard fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private static func syncDirectory(_ descriptor: Int32) throws {
        guard fsync(descriptor) == 0 else {
            let code = errno
            // Some filesystems do not support directory fsync. The descriptor
            // and atomic rename checks still provide the safety boundary.
            if code == EINVAL || code == ENOTSUP || code == EOPNOTSUPP {
                return
            }
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
    }
}
