import Foundation
import CryptoKit

// AAuth Secure Enclave Helper
// A codesigned CLI that manages persistent Secure Enclave keys.
// Called by Node.js via child_process.
//
// Usage:
//   se-helper generate <label>        — create key, print JSON with public JWK
//   se-helper sign <label> <hex-hash> — sign SHA-256 hash, print JSON with base64url signature
//   se-helper list                    — list all aauth keys, print JSON array
//   se-helper delete <label>          — delete a key
//   se-helper public-key <label>      — get public key for existing key

let args = CommandLine.arguments

guard args.count >= 2 else {
    printError("Usage: se-helper <generate|sign|list|delete|public-key> [args...]")
    exit(1)
}

let command = args[1]

do {
    switch command {
    case "generate":
        guard args.count >= 3 else {
            printError("Usage: se-helper generate <label>")
            exit(1)
        }
        try generateKey(label: args[2])

    case "sign":
        guard args.count >= 4 else {
            printError("Usage: se-helper sign <label> <hex-hash>")
            exit(1)
        }
        try signHash(label: args[2], hexHash: args[3])

    case "list":
        try listKeys()

    case "delete":
        guard args.count >= 3 else {
            printError("Usage: se-helper delete <label>")
            exit(1)
        }
        try deleteKey(label: args[2])

    case "public-key":
        guard args.count >= 3 else {
            printError("Usage: se-helper public-key <label>")
            exit(1)
        }
        try getPublicKey(label: args[2])

    default:
        printError("Unknown command: \(command)")
        exit(1)
    }
} catch {
    printError("\(error)")
    exit(1)
}

// MARK: - Commands

func generateKey(label: String) throws {
    guard SecureEnclave.isAvailable else {
        throw SEError.notAvailable
    }

    // Check if key already exists
    if (try? loadKeyData(label: label)) != nil {
        throw SEError.keyExists(label)
    }

    // Create key in Secure Enclave
    let key = try SecureEnclave.P256.Signing.PrivateKey(
        compactRepresentable: false
    )

    // Store the key's dataRepresentation in keychain
    // This is an opaque blob that CryptoKit can use to reconnect to the SE key
    let keyData = key.dataRepresentation

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecAttrAccount as String: label,
        kSecValueData as String: keyData,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw SEError.keychainError("SecItemAdd failed: \(status)")
    }

    let jwk = publicKeyToJWK(key.publicKey)
    let result: [String: Any] = [
        "label": label,
        "algorithm": "ES256",
        "publicJwk": jwk,
    ]
    printJSON(result)
}

func signHash(label: String, hexHash: String) throws {
    let key = try loadKey(label: label)
    let hashData = try hexToData(hexHash)

    guard hashData.count == 32 else {
        throw SEError.invalidHash("Expected 32 bytes (SHA-256), got \(hashData.count)")
    }

    // Sign the pre-computed hash using the SE key
    let signature = try key.signature(for: RawDigest(hashData))

    let rawSig = signature.rawRepresentation
    let sigB64 = base64url(rawSig)

    let result: [String: Any] = [
        "algorithm": "ES256",
        "signature": sigB64,
        "signatureLength": rawSig.count,
    ]
    printJSON(result)
}

func listKeys() throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    var keys: [[String: Any]] = []

    if status == errSecSuccess, let items = result as? [[String: Any]] {
        for item in items {
            if let account = item[kSecAttrAccount as String] as? String {
                keys.append([
                    "label": account,
                    "algorithm": "ES256",
                    "backend": "secure-enclave",
                ])
            }
        }
    }

    printJSON(keys)
}

func deleteKey(label: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecAttrAccount as String: label,
    ]

    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw SEError.keychainError("SecItemDelete failed: \(status)")
    }

    printJSON(["deleted": label])
}

func getPublicKey(label: String) throws {
    let key = try loadKey(label: label)
    let jwk = publicKeyToJWK(key.publicKey)
    printJSON([
        "label": label,
        "algorithm": "ES256",
        "publicJwk": jwk,
    ])
}

// MARK: - Key Loading

func loadKeyData(label: String) throws -> Data {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecAttrAccount as String: label,
        kSecReturnData as String: true,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess, let data = result as? Data else {
        throw SEError.keyNotFound(label)
    }

    return data
}

func loadKey(label: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let data = try loadKeyData(label: label)
    // dataRepresentation is an opaque handle that reconnects to the SE key
    return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
}

// MARK: - Helpers

func publicKeyToJWK(_ publicKey: P256.Signing.PublicKey) -> [String: String] {
    let raw = publicKey.rawRepresentation // 64 bytes: x || y
    let x = raw.prefix(32)
    let y = raw.suffix(32)

    return [
        "kty": "EC",
        "crv": "P-256",
        "x": base64url(x),
        "y": base64url(y),
        "alg": "ES256",
        "use": "sig",
    ]
}

/// Wraps pre-computed hash bytes so CryptoKit can sign them directly
struct RawDigest: Digest {
    static var byteCount = 32
    private var bytes: Data

    init(_ data: Data) {
        self.bytes = data
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    static func hash<D: DataProtocol>(data: D) -> RawDigest {
        fatalError("Not used")
    }

    typealias Bytes = Data

    func hash(into hasher: inout Hasher) {
        hasher.combine(bytes)
    }

    static func == (lhs: RawDigest, rhs: RawDigest) -> Bool {
        lhs.bytes == rhs.bytes
    }
}

func base64url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func base64url(_ data: some DataProtocol) -> String {
    base64url(Data(data))
}

func hexToData(_ hex: String) throws -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        guard nextIndex <= hex.endIndex,
              let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
            throw SEError.invalidHash("Invalid hex")
        }
        data.append(byte)
        index = nextIndex
    }
    return data
}

func printJSON(_ value: Any) {
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
       let str = String(data: data, encoding: .utf8) {
        print(str)
    }
}

func printError(_ message: String) {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
}

// MARK: - Errors

enum SEError: Error, CustomStringConvertible {
    case notAvailable
    case keyExists(String)
    case keyNotFound(String)
    case keychainError(String)
    case invalidHash(String)

    var description: String {
        switch self {
        case .notAvailable: return "Secure Enclave not available"
        case .keyExists(let l): return "Key already exists: \(l)"
        case .keyNotFound(let l): return "Key not found: \(l)"
        case .keychainError(let m): return "Keychain error: \(m)"
        case .invalidHash(let m): return "Invalid hash: \(m)"
        }
    }
}
