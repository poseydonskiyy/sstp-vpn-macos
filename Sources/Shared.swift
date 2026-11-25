import Foundation
import Darwin

struct Failure: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct VPNRoute: Codable, Hashable {
    let kind: String
    let destination: String

    var description: String { "\(kind) \(destination)" }
    var address: String { String(destination.split(separator: "/")[0]) }

    static func parse(_ text: String) throws -> [VPNRoute] {
        var routes: [VPNRoute] = []
        var seen: Set<VPNRoute> = []
        let lines = text.components(separatedBy: .newlines)
        for (index, line) in lines.enumerated() {
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            if parts.isEmpty || parts[0].hasPrefix("#") { continue }
            guard parts.count == 2, let route = parse(kind: parts[0], target: parts[1]) else {
                throw Failure("Строка \(index + 1): укажите host и IPv4 или net и подсеть IPv4 с префиксом от /1 до /32.")
            }
            if seen.insert(route).inserted { routes.append(route) }
        }
        guard routes.count <= 128 else { throw Failure("Можно добавить до 128 маршрутов.") }
        return routes
    }

    private static func parse(kind: String, target: String) -> VPNRoute? {
        let parts = target.split(separator: "/", omittingEmptySubsequences: false)
        guard let first = parts.first, let address = ipv4(String(first)) else { return nil }
        if kind == "host", parts.count == 1 {
            return VPNRoute(kind: kind, destination: addressString(address))
        }
        guard kind == "net", parts.count == 2, let prefix = Int(parts[1]),
              (1...32).contains(prefix) else { return nil }
        if prefix == 32 { return VPNRoute(kind: "host", destination: addressString(address)) }
        let network = address & (UInt32.max << (32 - prefix))
        return VPNRoute(kind: kind, destination: "\(addressString(network))/\(prefix)")
    }

    func contains(_ target: String) -> Bool {
        guard let network = Self.ipv4(address), let number = Self.ipv4(target) else { return false }
        if kind == "host" { return network == number }
        guard let prefix = Int(destination.split(separator: "/")[1]), (1...31).contains(prefix) else {
            return false
        }
        return number & (UInt32.max << (32 - prefix)) == network
    }

    static func ipv4(_ text: String) -> UInt32? {
        var result = in_addr()
        return inet_pton(AF_INET, text, &result) == 1 ? UInt32(bigEndian: result.s_addr) : nil
    }

    private static func addressString(_ address: UInt32) -> String {
        [24, 16, 8, 0].map { String((address >> $0) & 255) }.joined(separator: ".")
    }
}

enum PPPEncryption: String, Codable, CaseIterable, Identifiable {
    case none, optional, required, maximum

    var id: Self { self }

    var title: String {
        switch self {
        case .none: "Выключено"
        case .optional: "По согласованию"
        case .required: "Обязательно"
        case .maximum: "Обязательно (128 бит)"
        }
    }

    var options: [String] {
        switch self {
        case .none: ["nomppe"]
        case .optional: []
        case .required: ["require-mppe"]
        case .maximum: ["require-mppe-128"]
        }
    }
}

enum PPPAuthentication: String, Codable, CaseIterable, Identifiable {
    case mschapv2, chap, pap

    var id: Self { self }

    var title: String {
        switch self {
        case .mschapv2: "MS‑CHAPv2"
        case .chap: "CHAP"
        case .pap: "PAP"
        }
    }

    var refusalOption: String {
        switch self {
        case .mschapv2: "refuse-mschap-v2"
        case .chap: "refuse-chap"
        case .pap: "refuse-pap"
        }
    }
}

enum ServerTrustMode: String, Codable, CaseIterable, Identifiable {
    case system, custom

    var id: Self { self }
    var title: String {
        switch self {
        case .system: "Системное доверие macOS"
        case .custom: "Пользовательский комплект CA"
        }
    }
}

struct DNSRule: Codable {
    let suffix: String
    let servers: [String]

    init(suffix: String, servers: [String]) throws {
        self.suffix = try Profile.normalizedDNSSuffix(suffix)
        guard (1...8).contains(servers.count),
              servers.allSatisfy({ VPNRoute.ipv4($0).map { $0 != 0 && $0 < 0xe0000000 } == true }) else {
            throw Failure("Укажите от 1 до 8 IPv4-адресов DNS-серверов через запятую.")
        }
        self.servers = servers
    }
}

struct Profile: Codable {
    var server = ""
    var port = "443"
    var login = ""
    var routes = ""
    var remember = false
    var pppEncryption: PPPEncryption?
    var pppAuthentication: [PPPAuthentication]?
    var idleDisconnectSeconds: UInt32?
    var serverTrust: ServerTrustMode?
    var fullTunnel: Bool?
    var diagnoseInternet: Bool?
    var useSystemRouteForServer: Bool?
    var serverIPv4Override: String?
    var dnsSuffix: String?
    var dnsRules: [DNSRule]?
    var trustMode: ServerTrustMode { serverTrust ?? .system }
    var authentication: [PPPAuthentication] { pppAuthentication ?? [.mschapv2] }
    var authenticationOptions: [String] {
        ["refuse-eap", "refuse-mschap"] + PPPAuthentication.allCases
            .filter { !authentication.contains($0) }.map(\.refusalOption)
    }

    func validateAuthentication() throws {
        guard !authentication.isEmpty, Set(authentication).count == authentication.count else {
            throw Failure("Выберите хотя бы один метод аутентификации PPP.")
        }
        if pppEncryption == .required || pppEncryption == .maximum {
            guard authentication.contains(.mschapv2) else {
                throw Failure("Шифрование PPP Required или Maximum требует MS‑CHAPv2. Проверьте EncryptionLevel в профиле Windows.")
            }
        }
    }
    var usesSystemRouteForServer: Bool { fullTunnel != true && useSystemRouteForServer == true }

    func transportIPv4() throws -> String? {
        guard usesSystemRouteForServer, let address = serverIPv4Override?.trimmingCharacters(in: .whitespacesAndNewlines),
              !address.isEmpty else { return nil }
        guard let ip = VPNRoute.ipv4(address), ip != 0, ip < 0xe0000000 else {
            throw Failure("Укажите корректный IPv4-адрес для подключения к VPN-серверу.")
        }
        return address
    }

    private static func isDNSName(_ value: String) -> Bool {
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        return value.utf8.count <= 253 && !labels.isEmpty && labels.allSatisfy { label in
            label.utf8.count <= 63 && label.range(of: #"\A[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\z"#, options: .regularExpression) != nil
        }
    }

    static func normalizedDNSSuffix(_ value: String) throws -> String {
        let suffix = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard isDNSName(suffix), VPNRoute.ipv4(suffix) == nil else {
            throw Failure("Укажите корректное доменное имя для DNS-суффикса.")
        }
        return suffix.lowercased()
    }

    func validateEndpoint() throws {
        guard Self.isDNSName(server), let number = Int(port), port == String(number), (1...65535).contains(number) else {
            throw Failure("Введите имя сервера или IPv4 и порт от 1 до 65535.")
        }
    }

    func validatedDNSRules() throws -> [DNSRule] {
        let rules = dnsRules ?? []
        guard rules.count <= 32 else { throw Failure("Профиль поддерживает до 32 DNS-правил.") }
        var seen = Set<String>()
        return try rules.map { rule in
            let validated = try DNSRule(suffix: rule.suffix, servers: rule.servers)
            guard seen.insert(validated.suffix).inserted else {
                throw Failure("DNS-правило для \(validated.suffix) уже задано.")
            }
            return validated
        }
    }
}

struct VPNRequest: Codable {
    let profile: Profile
    let password: String
    let certificates: Data

    func validate() throws -> [VPNRoute] {
        try profile.validateEndpoint()
        try profile.validateAuthentication()
        _ = try profile.transportIPv4()
        if let suffix = profile.dnsSuffix { _ = try Profile.normalizedDNSSuffix(suffix) }
        _ = try profile.validatedDNSRules()
        guard !profile.login.isEmpty, !password.isEmpty, profile.login.utf8.count < 1024,
              password.utf8.count < 256, !profile.login.contains("\0"), !password.contains("\0"),
              !password.contains("\n"), !password.contains("\r"),
              certificates.count <= 256 * 1024,
              certificates.isEmpty == (profile.trustMode == .system),
              profile.routes.utf8.count <= 24 * 1024 else {
            throw Failure("Проверьте логин, пароль, список маршрутов и комплект сертификатов.")
        }
        return try VPNRoute.parse(profile.routes)
    }
}

struct VPNEvent: Codable {
    let type: String
    let message: String
}

enum Engine {
    static var executable: String? {
        let directory = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let path = directory.appendingPathComponent("sstpc").path
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }
}
