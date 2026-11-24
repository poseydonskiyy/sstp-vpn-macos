import Foundation
import Security

struct SavedProfile: Codable, Identifiable {
    let id: String
    let name: String
    var settings: Profile

    var title: String { id == ProfileLibrary.legacyID ? name : "\(name) · \(settings.server)" }
}

struct ProfileLibrary: Codable {
    static let legacyID = "vpn-profile"
    var profiles: [SavedProfile]
    var selectedID: String?

    var selected: SavedProfile? {
        profiles.first(where: { $0.id == selectedID }) ?? profiles.first
    }

    mutating func update(_ settings: Profile, id: String) {
        if let index = profiles.firstIndex(where: { $0.id == id }) {
            profiles[index].settings = settings
        }
    }

    mutating func remove(_ id: String) {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return }
        let wasSelected = selected?.id == id
        profiles.remove(at: index)
        if wasSelected {
            selectedID = profiles.isEmpty ? nil : profiles[min(index, profiles.count - 1)].id
        }
    }

    mutating func addWindows(_ imported: [WindowsProfile]) throws {
        for item in imported {
            if let index = profiles.firstIndex(where: {
                $0.id != Self.legacyID && $0.name.caseInsensitiveCompare(item.name) == .orderedSame &&
                $0.settings.server.caseInsensitiveCompare(item.settings.server) == .orderedSame &&
                $0.settings.port == item.settings.port
            }) {
                profiles[index].settings.routes = item.settings.routes
                profiles[index].settings.pppEncryption = item.settings.pppEncryption
                profiles[index].settings.fullTunnel = item.settings.fullTunnel
                profiles[index].settings.dnsSuffix = item.settings.dnsSuffix
                profiles[index].settings.dnsRules = item.settings.dnsRules
                selectedID = profiles[index].id
            } else {
                guard profiles.count < 128 else { throw Failure("В приложении можно хранить до 128 профилей.") }
                let profile = SavedProfile(id: UUID().uuidString, name: item.name, settings: item.settings)
                profiles.append(profile)
                selectedID = profile.id
            }
        }
    }
}

enum Storage {
    static let identifier = "ru.sstpgui.mac"
    static let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("SSTP VPN", isDirectory: true)
    static let customCA = folder.appendingPathComponent("ca.pem")
    static let profileURL = folder.appendingPathComponent("profile.json")
    static let libraryURL = folder.appendingPathComponent("profiles.json")

    static func prepare() throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
    }

    static func save(_ library: ProfileLibrary) throws {
        try prepare()
        try JSONEncoder().encode(library).write(to: libraryURL, options: .atomic)
    }

    static func load() -> ProfileLibrary {
        if let data = try? Data(contentsOf: libraryURL),
           let library = try? JSONDecoder().decode(ProfileLibrary.self, from: data) {
            return library
        }
        let profile = (try? Data(contentsOf: profileURL)).flatMap { try? JSONDecoder().decode(Profile.self, from: $0) }
        let initial = SavedProfile(id: ProfileLibrary.legacyID, name: "Основной профиль", settings: profile ?? Profile())
        return ProfileLibrary(profiles: [initial], selectedID: initial.id)
    }

    static func removeLegacySnapshot() throws {
        do { try FileManager.default.removeItem(at: profileURL) }
        catch let error as CocoaError where error.code == .fileNoSuchFile {}
    }

    private static func key(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: identifier,
         kSecAttrAccount as String: id]
    }

    static func readPassword(_ id: String) -> String {
        var query = key(id)
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func savePassword(_ password: String?, for id: String) throws {
        let key = key(id)
        let status: OSStatus
        if let password {
            let values = [kSecValueData as String: Data(password.utf8)]
            let updated = SecItemUpdate(key as CFDictionary, values as CFDictionary)
            status = updated == errSecItemNotFound
                ? SecItemAdd(key.merging(values) { _, new in new } as CFDictionary, nil)
                : updated
        } else {
            let deleted = SecItemDelete(key as CFDictionary)
            status = deleted == errSecItemNotFound ? errSecSuccess : deleted
        }
        guard status == errSecSuccess else {
            let message = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? String(status)
            throw Failure("Связка ключей: \(message)")
        }
    }
}
