import Foundation
import Security

/// API credentials live only in the user's Keychain. They are handed to the
/// engine in memory at launch and never written anywhere else.
struct KeychainStore: Sendable {
    let service: String

    static let credentials = KeychainStore(service: "io.portseif.Spectre.credentials")

    private func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    func save(_ secret: String, account: String) throws {
        let data = Data(secret.utf8)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrLabel as String: "Spectre: \(account)",
        ]
        var status = SecItemUpdate(query(account) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query(account).merging(attributes) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    func read(account: String) throws -> String? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return nil }
            return String(decoding: data, as: UTF8.self)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError(status: status)
        }
    }

    func delete(account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status: status) }
    }
}

struct KeychainError: LocalizedError, Sendable {
    let status: OSStatus

    var errorDescription: String? {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
        return "Keychain error \(status): \(message)"
    }
}

/// Credential identifiers shared with the engine (`spectre_core::credentials::ids`).
enum CredentialID: String, CaseIterable, Identifiable, Sendable {
    case hibp
    case github

    var id: String { rawValue }

    var title: String {
        switch self {
        case .hibp: "Have I Been Pwned API key"
        case .github: "GitHub token (optional)"
        }
    }

    var help: String {
        switch self {
        case .hibp: "Required for account breach lookups of ownership-verified addresses. Get a key at haveibeenpwned.com/API/Key."
        case .github: "Raises GitHub's 60 requests/hour unauthenticated limit. A fine-grained token with no permissions is enough."
        }
    }
}
