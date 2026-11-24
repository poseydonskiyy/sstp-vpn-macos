import Foundation

struct WindowsProfile {
    let name: String
    var settings: Profile
}

enum WindowsConfig {
    static func decode(_ data: Data) throws -> String {
        guard data.count <= 256 * 1024 else { throw Failure("Размер скрипта Windows должен быть до 256 КБ.") }
        let bom = data.prefix(2)
        let encoding: String.Encoding = bom == Data([0xff, 0xfe]) || bom == Data([0xfe, 0xff]) ? .utf16 : .utf8
        guard let text = String(data: data, encoding: encoding) else {
            throw Failure("Откройте файл PowerShell в UTF-8 или UTF-16 с BOM.")
        }
        return text
    }

    static func parse(_ text: String) throws -> [WindowsProfile] {
        guard text.utf8.count <= 256 * 1024 else { throw Failure("Размер скрипта Windows должен быть до 256 КБ.") }
        var profiles: [WindowsProfile] = []
        var routes: [(name: String, prefix: String, line: Int)] = []
        var dnsRules: [(name: String, rule: DNSRule, line: Int)] = []
        for command in try commands(text) {
            let words = command.words
            let line = command.line
            switch words[0].lowercased() {
            case "add-vpnconnection", "vpnclient\\add-vpnconnection":
                let args = try arguments(Array(words.dropFirst()), line: line,
                                         values: ["name", "serveraddress", "tunneltype", "authenticationmethod", "encryptionlevel", "dnssuffix"],
                                         switches: ["splittunneling", "remembercredential", "passthru", "force", "alluserconnection"])
                guard let name = args["name"], !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      name.utf8.count <= 160 else { throw issue(line, "Укажите имя профиля в -Name.") }
                guard args["tunneltype"]?.lowercased() == "sstp" else {
                    throw issue(line, "Требуется явный -TunnelType SSTP.")
                }
                guard (args["authenticationmethod"]?.lowercased() ?? "mschapv2") == "mschapv2" else {
                    throw issue(line, "Поддерживается -AuthenticationMethod MSCHAPv2.")
                }
                let level = args["encryptionlevel"]?.lowercased() ?? "required"
                guard let encryption = level == "noencryption" ? PPPEncryption.none : PPPEncryption(rawValue: level) else {
                    throw issue(line, "Поддерживаются уровни EncryptionLevel NoEncryption, Optional, Required и Maximum.")
                }
                guard let address = args["serveraddress"] else {
                    throw issue(line, "Укажите сервер в -ServerAddress.")
                }
                var settings = Profile()
                let endpoint = address.split(separator: ":", omittingEmptySubsequences: false)
                guard (1...2).contains(endpoint.count) else { throw issue(line, "Укажите имя сервера или IPv4.") }
                settings.server = String(endpoint[0])
                if endpoint.count == 2 { settings.port = String(endpoint[1]) }
                do {
                    try settings.validateEndpoint()
                    settings.dnsSuffix = try args["dnssuffix"].map(Profile.normalizedDNSSuffix)
                }
                catch { throw issue(line, error.localizedDescription) }
                settings.remember = args["remembercredential"] == "true"
                settings.pppEncryption = encryption
                settings.fullTunnel = args["splittunneling"] != "true"
                guard !profiles.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
                    throw issue(line, "Имя профиля «\(name)» повторяется.")
                }
                profiles.append(WindowsProfile(name: name, settings: settings))
            case "add-vpnconnectionroute", "vpnclient\\add-vpnconnectionroute":
                let args = try arguments(Array(words.dropFirst()), line: line,
                                         values: ["connectionname", "destinationprefix", "routemetric"],
                                         switches: ["passthru", "alluserconnection"])
                guard let name = args["connectionname"], let prefix = args["destinationprefix"] else {
                    throw issue(line, "Укажите -ConnectionName и -DestinationPrefix.")
                }
                if let metric = args["routemetric"], UInt32(metric) == nil {
                    throw issue(line, "Укажите целое неотрицательное значение -RouteMetric.")
                }
                do { _ = try VPNRoute.parse("net " + prefix) }
                catch { throw issue(line, "Маршрут должен быть подсетью IPv4 с префиксом /1–/32.") }
                routes.append((name, prefix, line))
            case "add-vpnconnectiontriggerdnsconfiguration", "vpnclient\\add-vpnconnectiontriggerdnsconfiguration":
                let args = try arguments(Array(words.dropFirst()), line: line,
                                         values: ["connectionname", "dnssuffix", "dnsipaddress"],
                                         switches: ["passthru", "force"], list: "dnsipaddress")
                guard let name = args["connectionname"], let suffix = args["dnssuffix"],
                      let addresses = args["dnsipaddress"] else {
                    throw issue(line, "Для DNS-правила укажите -ConnectionName, -DnsSuffix и -DnsIPAddress.")
                }
                let servers = addresses.components(separatedBy: ",").map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
                do { dnsRules.append((name, try DNSRule(suffix: suffix, servers: servers), line)) }
                catch { throw issue(line, error.localizedDescription) }
            default:
                throw issue(line, "Ожидается Add-VpnConnection, Add-VpnConnectionRoute или Add-VpnConnectionTriggerDnsConfiguration.")
            }
        }
        guard !profiles.isEmpty, profiles.count <= 32 else {
            throw Failure("Добавьте от 1 до 32 команд Add-VpnConnection.")
        }
        var routeLines = Array(repeating: [String](), count: profiles.count)
        for route in routes {
            guard let index = profiles.firstIndex(where: { $0.name.caseInsensitiveCompare(route.name) == .orderedSame }) else {
                throw issue(route.line, "В тексте отсутствует профиль «\(route.name)» для маршрута.")
            }
            routeLines[index].append("net " + route.prefix)
        }
        for entry in dnsRules {
            guard let index = profiles.firstIndex(where: { $0.name.caseInsensitiveCompare(entry.name) == .orderedSame }) else {
                throw issue(entry.line, "В тексте отсутствует профиль «\(entry.name)» для DNS-правила.")
            }
            if profiles[index].settings.dnsRules == nil { profiles[index].settings.dnsRules = [] }
            profiles[index].settings.dnsRules?.append(entry.rule)
            do { _ = try profiles[index].settings.validatedDNSRules() }
            catch { throw issue(entry.line, error.localizedDescription) }
        }
        for index in profiles.indices {
            profiles[index].settings.routes = try VPNRoute.parse(routeLines[index].joined(separator: "\n"))
                .map(\.description).joined(separator: "\n")
        }
        return profiles
    }

    private static func arguments(_ words: [String], line: Int, values: Set<String>,
                                  switches: Set<String>, list: String? = nil) throws -> [String: String] {
        var result: [String: String] = [:]
        var index = 0
        while index < words.count {
            let word = words[index]
            index += 1
            guard isParameter(word) else { throw issue(line, "Ожидается именованный параметр PowerShell.") }
            let parts = word.dropFirst().split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            var key = parts.first?.lowercased() ?? ""
            if key == "name", values.contains("connectionname") { key = "connectionname" }
            guard result[key] == nil else { throw issue(line, "Параметр \(word) повторяется.") }
            let immediate = parts.count == 2 ? String(parts[1]) : nil
            if switches.contains(key) {
                switch immediate?.lowercased() {
                case nil, "$true": result[key] = "true"
                case "$false": result[key] = "false"
                default: throw issue(line, "Для \(word) допустимы :$true и :$false.")
                }
            } else if values.contains(key) {
                if let immediate {
                    result[key] = immediate
                } else {
                    guard index < words.count, !isParameter(words[index]) else {
                        throw issue(line, "Укажите значение для \(word).")
                    }
                    result[key] = words[index]
                    index += 1
                }
                if key == list {
                    while index < words.count, !isParameter(words[index]) {
                        result[key, default: ""] += " " + words[index]
                        index += 1
                    }
                }
                guard let value = result[key], !value.isEmpty, !value.contains("$") else {
                    throw issue(line, "Задайте для \(word) текстовое значение без переменных.")
                }
            } else {
                throw issue(line, "Параметр \(word) не поддерживается при импорте.")
            }
        }
        return result
    }

    private static func isParameter(_ word: String) -> Bool {
        word.first.map { "-–—―".contains($0) } ?? false
    }

    private struct Command {
        let line: Int
        let words: [String]
    }

    private static func commands(_ source: String) throws -> [Command] {
        let source = source.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
        var iterator = source.makeIterator()
        var character = iterator.next()
        var line = 1
        var start = 1
        var words: [String] = []
        var token = ""
        var quote: Character?
        var inToken = false
        var result: [Command] = []

        func endToken() {
            if inToken { words.append(token) }
            token = ""
            inToken = false
        }

        while let current = character {
            character = iterator.next()
            if current == "`", quote != "'" {
                guard let escaped = character else { throw issue(line, "Незаконченный перенос или escape PowerShell.") }
                character = iterator.next()
                if escaped == "\n" { line += 1 }
                else {
                    guard ["`", "\"", " ", "'"].contains(escaped) else {
                        throw issue(line, "Неподдерживаемый escape PowerShell.")
                    }
                    token.append(escaped)
                    inToken = true
                }
            } else if let delimiter = quote {
                if current == delimiter {
                    if character == delimiter {
                        token.append(current)
                        character = iterator.next()
                    } else { quote = nil }
                } else if current == "\n" {
                    throw issue(line, "Незакрытые кавычки.")
                } else { token.append(current) }
            } else if current == "'" || current == "\"" {
                quote = current
                inToken = true
            } else if current == "#" {
                while let next = character, next != "\n" { character = iterator.next() }
            } else if current == "\n" || current == ";" {
                endToken()
                if !words.isEmpty { result.append(Command(line: start, words: words)) }
                words.removeAll(keepingCapacity: true)
                if current == "\n" { line += 1 }
                start = line
            } else if current.isWhitespace || current == "\u{FEFF}" {
                endToken()
            } else {
                if "|&(){}<>".contains(current) {
                    throw issue(line, "Вставьте команды с готовыми значениями без выражений PowerShell.")
                }
                token.append(current)
                inToken = true
            }
        }
        guard quote == nil else { throw issue(line, "Незакрытые кавычки.") }
        endToken()
        if !words.isEmpty { result.append(Command(line: start, words: words)) }
        return result
    }

    private static func issue(_ line: Int, _ message: String) -> Failure {
        Failure("Строка \(line): \(message)")
    }
}
