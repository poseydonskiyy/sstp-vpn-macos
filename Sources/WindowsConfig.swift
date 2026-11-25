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
        var parser = PowerShellProfileScript(tokens: try PowerShellProfileScript.lex(text))
        let commands = try parser.readCommands()
        var profiles: [WindowsProfile] = []
        var changes: [PowerShellProfileScript.Command] = []
        var byName: [String: Int] = [:]
        var connectionLines: [Int] = []
        for cmd in commands {
            guard cmd.name == "add-vpnconnection" else {
                changes.append(cmd)
                continue
            }
            let name = try cmd.required("name")
            guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, name.utf8.count <= 160 else {
                throw cmd.issue("Укажите имя профиля в -Name.")
            }
            guard byName[name.lowercased()] == nil else { throw cmd.issue("Имя профиля «\(name)» повторяется.") }
            guard profiles.count < 32 else { throw cmd.issue("В одном файле можно импортировать до 32 профилей.") }
            guard cmd.scalar("tunneltype")?.lowercased() == "sstp" else {
                throw cmd.issue("Требуется явный -TunnelType SSTP.")
            }
            var settings = Profile()
            settings.fullTunnel = true
            settings.pppEncryption = .required
            _ = try cmd.required("serveraddress")
            try applyConnection(cmd, to: &settings)
            byName[name.lowercased()] = profiles.count
            profiles.append(WindowsProfile(name: name, settings: settings))
            connectionLines.append(cmd.line)
        }
        guard !profiles.isEmpty else { throw Failure("Добавьте команду Add-VpnConnection для профиля SSTP.") }
        for cmd in changes {
            let name = try cmd.required(cmd.name == "set-vpnconnection" ? "name" : "connectionname")
            guard let index = byName[name.lowercased()] else { throw cmd.issue("В тексте отсутствует профиль «\(name)».") }
            switch cmd.name {
            case "set-vpnconnection":
                try applyConnection(cmd, to: &profiles[index].settings)
                connectionLines[index] = cmd.line
            case "add-vpnconnectionroute", "remove-vpnconnectionroute":
                do {
                    let prefix = try cmd.required("destinationprefix")
                    guard let route = try VPNRoute.parse("net " + prefix).first else {
                        throw Failure("Укажите IPv4-подсеть в -DestinationPrefix.")
                    }
                    var routes = try VPNRoute.parse(profiles[index].settings.routes)
                    if cmd.name.hasPrefix("remove-") {
                        routes.removeAll { $0 == route }
                    } else if !routes.contains(route) {
                        guard routes.count < 128 else { throw Failure("Можно добавить до 128 маршрутов.") }
                        routes.append(route)
                    }
                    profiles[index].settings.routes = routes.map(\.description).joined(separator: "\n")
                } catch { throw cmd.issue(error.localizedDescription) }
            default:
                try applyDNS(cmd, to: &profiles[index].settings)
            }
        }
        for (profile, line) in zip(profiles, connectionLines) {
            do { try profile.settings.validateAuthentication() }
            catch { throw PowerShellProfileScript.issue(line, error.localizedDescription) }
        }
        return profiles
    }

    private static func applyConnection(_ cmd: PowerShellProfileScript.Command, to profile: inout Profile) throws {
        if let tunnel = cmd.scalar("tunneltype"), tunnel.lowercased() != "sstp" {
            throw cmd.issue("Поддерживается -TunnelType SSTP.")
        }
        if cmd.args["eapconfigxmlstream"] != nil {
            throw cmd.issue("-EapConfigXmlStream требует поддержку EAP в сетевом компоненте.")
        }
        if let methods = cmd.args["authenticationmethod"] {
            let authentication = try methods.map { method in
                guard let supported = PPPAuthentication(rawValue: method.lowercased()) else {
                    throw cmd.issue("Метод \(method) пока недоступен. Поддерживаются MSCHAPv2, CHAP и PAP.")
                }
                return supported
            }
            profile.pppAuthentication = PPPAuthentication.allCases.filter { authentication.contains($0) }
        }
        if let level = cmd.scalar("encryptionlevel")?.lowercased() {
            guard let encryption = level == "noencryption" ? PPPEncryption.none : PPPEncryption(rawValue: level) else {
                throw cmd.issue("Поддерживаются уровни EncryptionLevel NoEncryption, Optional, Required и Maximum.")
            }
            profile.pppEncryption = encryption
        }
        do {
            if let address = cmd.scalar("serveraddress") {
                let endpoint = address.split(separator: ":", omittingEmptySubsequences: false)
                guard (1...2).contains(endpoint.count) else { throw Failure("Укажите имя сервера или IPv4.") }
                profile.server = String(endpoint[0])
                profile.port = endpoint.count == 2 ? String(endpoint[1]) : "443"
                try profile.validateEndpoint()
            }
            if let suffix = cmd.scalar("dnssuffix") {
                profile.dnsSuffix = suffix.isEmpty ? nil : try Profile.normalizedDNSSuffix(suffix)
            }
        } catch { throw cmd.issue(error.localizedDescription) }
        if let split = cmd.scalar("splittunneling") { profile.fullTunnel = split != "true" }
        if let remember = cmd.scalar("remembercredential") { profile.remember = remember == "true" }
        if let timeout = cmd.scalar("idledisconnectseconds") {
            guard let seconds = UInt32(timeout), seconds <= Int32.max else {
                throw cmd.issue("Укажите -IdleDisconnectSeconds от 0 до \(Int32.max).")
            }
            profile.idleDisconnectSeconds = seconds
        }
    }

    private static func applyDNS(_ cmd: PowerShellProfileScript.Command, to profile: inout Profile) throws {
        do {
            let suffix = try Profile.normalizedDNSSuffix(cmd.required("dnssuffix"))
            var rules = profile.dnsRules ?? []
            if cmd.name.hasPrefix("remove-") {
                rules.removeAll { $0.suffix == suffix }
            } else {
                guard let addresses = cmd.args["dnsipaddress"] else {
                    throw Failure("Укажите -DnsIPAddress. Для одного суффикса поиска используйте -DnsSuffix в Add-VpnConnection.")
                }
                let servers = addresses.flatMap { $0.components(separatedBy: ",") }
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                let rule = try DNSRule(suffix: suffix, servers: servers)
                if cmd.name.hasPrefix("set-") {
                    rules.removeAll { $0.suffix == suffix }
                }
                rules.append(rule)
            }
            profile.dnsRules = rules
            _ = try profile.validatedDNSRules()
        } catch { throw cmd.issue(error.localizedDescription) }
    }
}

private struct PowerShellProfileScript {
    struct Command {
        let name: String
        let line: Int
        let args: [String: [String]]

        func scalar(_ key: String) -> String? { args[key]?.first }

        func required(_ key: String) throws -> String {
            guard let value = scalar(key), !value.isEmpty else { throw issue("Укажите -\(key).") }
            return value
        }

        func issue(_ message: String) -> Failure { PowerShellProfileScript.issue(line, message) }
    }

    enum Kind: Equatable {
        case word(String), quoted(String, expand: Bool), newline, separator, comma, equals
        case startArray, endArray, startMap, endMap, pipe
    }

    struct Token {
        let kind: Kind
        let line: Int
    }

    enum Constant {
        case values([String]), map([String: [String]])
    }

    let tokens: [Token]
    private var position = 0
    private var constants: [String: Constant] = [:]

    init(tokens: [Token]) { self.tokens = tokens }

    private var current: Token? { position < tokens.count ? tokens[position] : nil }
    private var line: Int { current?.line ?? tokens.last?.line ?? 1 }

    @discardableResult
    private mutating func take(_ kind: Kind) -> Bool {
        guard current?.kind == kind else { return false }
        position += 1
        return true
    }

    private mutating func skipSeparators() {
        while take(.newline) || take(.separator) {}
    }

    mutating func readCommands() throws -> [Command] {
        var commands: [Command] = []
        skipSeparators()
        while let token = current {
            guard case .word(let name) = token.kind else {
                throw Self.issue(token.line, "Ожидается команда VpnClient или объявление переменной.")
            }
            position += 1
            if Self.identifier(name, prefix: "$") != nil, take(.equals) {
                try readAssignment(name, line: token.line)
            } else {
                let cmd = try readCommand(name, line: token.line)
                if cmd.scalar("whatif") != "true" { commands.append(cmd) }
            }
            guard current == nil || current?.kind == .newline || current?.kind == .separator else {
                throw Self.issue(line, "Ожидается конец команды.")
            }
            skipSeparators()
        }
        return commands
    }

    private mutating func readAssignment(_ name: String, line: Int) throws {
        let key = String(name.dropFirst()).lowercased()
        guard key != "true" && key != "false" && key != "null" else {
            throw Self.issue(line, "Эту переменную PowerShell нельзя переопределить.")
        }
        if take(.startMap) {
            var map: [String: [String]] = [:]
            skipSeparators()
            while !take(.endMap) {
                let fieldLine = self.line
                let field = try value()
                guard field.count == 1, take(.equals) else {
                    throw Self.issue(fieldLine, "В таблице параметров ожидается Имя = значение.")
                }
                let parameter = field[0].lowercased()
                guard map[parameter] == nil else { throw Self.issue(fieldLine, "Параметр -\(parameter) повторяется.") }
                map[parameter] = try values()
                if current?.kind != .endMap {
                    guard current?.kind == .newline || current?.kind == .separator else {
                        throw Self.issue(self.line, "Закройте таблицу } или добавьте следующую строку параметров.")
                    }
                    skipSeparators()
                }
            }
            constants[key] = .map(map)
        } else {
            constants[key] = .values(try values())
        }
    }

    private mutating func readCommand(_ raw: String, line: Int) throws -> Command {
        let short = raw.lowercased()
        let name = short.hasPrefix("vpnclient\\") ? String(short.dropFirst(10)) : short
        guard let spec = Self.commands[name] else {
            throw Self.issue(line, "Команда «\(raw)» не поддерживается при импорте профиля SSTP.")
        }
        var args: [String: [String]] = [:]
        var positional: [[String]] = []
        while let token = current, token.kind != .newline && token.kind != .separator {
            if take(.pipe) {
                while take(.newline) {}
                guard let next = current, case .word(let sink) = next.kind,
                      sink.caseInsensitiveCompare("Out-Null") == .orderedSame else {
                    throw Self.issue(token.line, "Поддерживается вывод команды через | Out-Null.")
                }
                position += 1
                break
            }
            if case .word(let word) = token.kind, let variable = Self.identifier(word, prefix: "@") {
                guard case .map(let map) = constants[variable] else {
                    throw Self.issue(token.line, "Объявите таблицу \(word) перед командой.")
                }
                position += 1
                for key in map.keys.sorted() {
                    try Self.insert(key, values: map[key], into: &args, spec: spec, line: token.line)
                }
            } else if case .word(let word) = token.kind, let parameter = Self.parameter(word) {
                position += 1
                let key = spec.key(parameter.key)
                let argument: [String]?
                if let attached = parameter.attached, !attached.isEmpty {
                    var values = try resolve(attached, line: token.line)
                    while take(.comma) {
                        while take(.newline) {}
                        try append(value(), to: &values)
                    }
                    argument = values
                } else if parameter.attached != nil || !spec.switches.contains(key) {
                    guard !isParameterOrEnd else { throw Self.issue(token.line, "Укажите значение для -\(key).") }
                    argument = try values()
                } else {
                    argument = nil
                }
                try Self.insert(key, values: argument, into: &args, spec: spec, line: token.line)
            } else {
                positional.append(try values())
            }
        }
        let slots = spec.positions.filter { args[$0] == nil }
        guard positional.count <= slots.count else { throw Self.issue(line, "Слишком много позиционных аргументов.") }
        for (key, argument) in zip(slots, positional) {
            try Self.insert(key, values: argument, into: &args, spec: spec, line: line)
        }
        return Command(name: name, line: line, args: args)
    }

    private static func insert(_ raw: String, values: [String]?, into args: inout [String: [String]],
                               spec: Spec, line: Int) throws {
        let key = spec.key(raw)
        guard args[key] == nil else { throw issue(line, "Параметр -\(key) повторяется.") }
        if spec.switches.contains(key) {
            let flags = values ?? ["true"]
            guard flags.count == 1, let flag = flags.first?.lowercased(), ["true", "false"].contains(flag) else {
                throw issue(line, "Для -\(key) допустимы \u{24}true и \u{24}false.")
            }
            args[key] = [flag]
        } else if spec.values.contains(key) || spec.lists.contains(key) {
            guard let values, !values.isEmpty, spec.lists.contains(key) || values.count == 1 else {
                throw issue(line, "Укажите значение для -\(key).")
            }
            if key == "routemetric", UInt32(values[0]) == nil {
                throw issue(line, "Укажите неотрицательное целое число для -RouteMetric.")
            }
            args[key] = values
        } else {
            throw issue(line, "Параметр -\(key) не поддерживается при импорте.")
        }
    }

    private var isParameterOrEnd: Bool {
        guard let token = current else { return true }
        if case .word(let word) = token.kind { return Self.parameter(word) != nil }
        return [.newline, .separator, .pipe, .endMap, .endArray].contains(token.kind)
    }

    private mutating func values() throws -> [String] {
        var result = try value()
        while take(.comma) {
            while take(.newline) {}
            try append(value(), to: &result)
        }
        return result
    }

    private mutating func value() throws -> [String] {
        if take(.startArray) {
            var result: [String] = []
            skipSeparators()
            while !take(.endArray) {
                try append(atom(), to: &result)
                if take(.comma) || current?.kind == .newline || current?.kind == .separator {
                    skipSeparators()
                    continue
                }
                guard current?.kind == .endArray else { throw Self.issue(line, "Закройте массив скобкой ).") }
            }
            return result
        }
        return try atom()
    }

    private func append(_ values: [String], to result: inout [String]) throws {
        guard values.count <= 128 - result.count else {
            throw Self.issue(line, "Один список PowerShell может содержать до 128 элементов.")
        }
        result += values
    }

    private mutating func atom() throws -> [String] {
        guard let token = current else { throw Self.issue(line, "Ожидается значение PowerShell.") }
        position += 1
        switch token.kind {
        case .word(let text):
            guard Self.parameter(text) == nil else { throw Self.issue(token.line, "Ожидается значение перед \(text).") }
            return try resolve(text, line: token.line)
        case .quoted(let text, let expand):
            if expand, text.contains("$") { return try resolve(text, line: token.line) }
            return [text]
        default: throw Self.issue(token.line, "Ожидается литерал или объявленная переменная PowerShell.")
        }
    }

    private func resolve(_ text: String, line: Int) throws -> [String] {
        guard text.contains("$") else { return [text] }
        guard let name = Self.identifier(text, prefix: "$") else {
            throw Self.issue(line, "Подставьте готовое значение вместо выражения PowerShell.")
        }
        if name == "true" || name == "false" { return [name] }
        guard case .values(let values) = constants[name] else {
            throw Self.issue(line, "Объявите переменную \(text) с готовым значением перед командой.")
        }
        return values
    }

    private struct Spec {
        let positions: [String]
        let values: Set<String>
        let lists: Set<String>
        let switches: Set<String>

        init(positions: [String], values: Set<String> = [], lists: Set<String> = [],
             switches: Set<String> = []) {
            self.positions = positions
            self.values = values.union(positions).subtracting(lists).subtracting(switches)
                .union(["erroraction", "warningaction", "informationaction", "progressaction",
                        "errorvariable", "warningvariable", "informationvariable", "outvariable",
                        "outbuffer", "pipelinevariable", "throttlelimit"])
            self.lists = lists
            self.switches = switches.union(["passthru", "force", "alluserconnection", "confirm",
                                            "whatif", "asjob", "verbose", "debug"])
        }

        func key(_ raw: String) -> String {
            switch raw {
            case "connectionname" where positions.first == "name": "name"
            case "name" where positions.first == "connectionname": "connectionname"
            case "ea": "erroraction"
            case "wa": "warningaction"
            case "ev": "errorvariable"
            case "ov": "outvariable"
            case "ob": "outbuffer"
            case "iv": "informationvariable"
            case "wv": "warningvariable"
            case "infa": "informationaction"
            case "proga": "progressaction"
            case "pv": "pipelinevariable"
            case "wi": "whatif"
            case "cf": "confirm"
            case "vb": "verbose"
            case "db": "debug"
            default: raw
            }
        }
    }

    private static let connection = Spec(
        positions: ["name", "serveraddress", "tunneltype", "encryptionlevel", "authenticationmethod", "splittunneling"],
        values: ["dnssuffix", "eapconfigxmlstream", "idledisconnectseconds"], lists: ["authenticationmethod"],
        switches: ["splittunneling", "remembercredential", "usewinlogoncredential"])
    private static let route = Spec(positions: ["connectionname", "destinationprefix", "routemetric"])
    private static let dns = Spec(positions: ["connectionname", "dnssuffix", "dnsipaddress"], lists: ["dnsipaddress"])
    private static let commands = [
        "add-vpnconnection": connection, "set-vpnconnection": connection,
        "add-vpnconnectionroute": route, "remove-vpnconnectionroute": route,
        "add-vpnconnectiontriggerdnsconfiguration": dns, "set-vpnconnectiontriggerdnsconfiguration": dns,
        "remove-vpnconnectiontriggerdnsconfiguration": Spec(positions: ["connectionname", "dnssuffix"]),
    ]

    private static func identifier(_ value: String, prefix: Character) -> String? {
        guard value.first == prefix else { return nil }
        let name = value.dropFirst()
        guard name.first.map({ $0.isLetter || $0 == "_" }) == true,
              name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }) else { return nil }
        return name.lowercased()
    }

    private static func parameter(_ text: String) -> (key: String, attached: String?)? {
        guard let first = text.first, "-–—―".contains(first) else { return nil }
        let parts = text.dropFirst().split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.first?.first?.isLetter == true else { return nil }
        return (parts[0].lowercased(), parts.count == 2 ? String(parts[1]) : nil)
    }

    static func lex(_ source: String) throws -> [Token] {
        let source = source.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
        var iterator = source.makeIterator()
        var next = iterator.next()
        var line = 1
        var start = 1
        var word = ""
        var tokens: [Token] = []
        func flush() {
            if !word.isEmpty { tokens.append(Token(kind: .word(word), line: start)) }
            word = ""
        }
        func append(_ kind: Kind) {
            flush()
            tokens.append(Token(kind: kind, line: line))
        }
        func consume() -> Character? {
            defer { next = iterator.next() }
            return next
        }
        func quoteType(_ value: Character) -> Character? {
            if "'‘’".contains(value) { return "'" }
            if "\"“”".contains(value) { return "\"" }
            return nil
        }
        while let ch = consume() {
            if ch == "`", next == "\n" {
                _ = consume()
                line += 1
            } else if let quote = quoteType(ch) {
                flush()
                var text = ""
                var closed = false
                while let char = consume(), char != "\n" {
                    if quoteType(char) == quote {
                        if let next, quoteType(next) == quote {
                            text.append(char)
                            _ = consume()
                        } else {
                            closed = true
                            break
                        }
                    } else if quote == "\"", char == "`" {
                        guard let escape = consume(), ["`", "\"", "'", " "].contains(escape) else {
                            throw issue(line, "Неподдерживаемая escape-последовательность PowerShell.")
                        }
                        text.append(escape)
                    } else {
                        text.append(char)
                    }
                }
                guard closed else { throw issue(line, "Незакрытые кавычки.") }
                append(.quoted(text, expand: quote == "\""))
            } else if ch == "<", next == "#" {
                flush()
                _ = consume()
                let beginning = line
                var closed = false
                while let char = consume() {
                    if char == "#", next == ">" {
                        _ = consume()
                        closed = true
                        break
                    }
                    if char == "\n" { line += 1 }
                }
                guard closed else { throw issue(beginning, "Незакрытый комментарий <# … #>.") }
            } else if ch == "#", word.isEmpty {
                while let char = next, char != "\n" { _ = consume() }
            } else if ch == "@", next == "(" || next == "{" {
                if consume() == "(" { append(.startArray) }
                else { append(.startMap) }
            } else if let kind: Kind = ["\n": .newline, ";": .separator, ",": .comma, "=": .equals,
                                         ")": .endArray, "}": .endMap, "|": .pipe][ch] {
                append(kind)
                if ch == "\n" { line += 1 }
            } else if ch.isWhitespace || ch == "\u{FEFF}" {
                flush()
            } else {
                if word.isEmpty { start = line }
                if ch == "`" {
                    guard let escape = consume(), ["`", "\"", "'", " "].contains(escape) else {
                        throw issue(line, "Неподдерживаемая escape-последовательность PowerShell.")
                    }
                    word.append(escape)
                } else {
                    guard !"&(){}<>".contains(ch) else {
                        throw issue(line, "Вставьте команды с готовыми значениями вместо выражений PowerShell.")
                    }
                    word.append(ch)
                }
            }
        }
        flush()
        return tokens
    }

    static func issue(_ line: Int, _ message: String) -> Failure {
        Failure("Строка \(line): \(message)")
    }
}
