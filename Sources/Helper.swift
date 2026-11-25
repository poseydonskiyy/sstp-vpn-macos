import Foundation
import Darwin
import SystemConfiguration

private let routePath = "/sbin/route"
private let outputLock = NSLock()

private func emit(_ type: String, _ message: String) {
    outputLock.lock()
    defer { outputLock.unlock() }
    if let encoded = try? JSONEncoder().encode(VPNEvent(type: type, message: message)) {
        var line = encoded
        line.append(10)
        _ = try? FileHandle.standardOutput.write(contentsOf: line)
    }
}

private final class StopSignal {
    private let lock = NSLock()
    private var received = false
    var requested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return received
    }

    func request() {
        lock.lock()
        received = true
        lock.unlock()
    }

    func check() throws {
        if requested { throw CancellationError() }
    }
}

private func capture(_ path: String, _ args: [String]) throws -> (status: Int32, text: String) {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = args
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: data, as: UTF8.self))
}

private func fields(_ text: String) -> [String: String] {
    var result: [String: String] = [:]
    for line in text.split(separator: "\n") {
        let parts = line.split(separator: ":", maxSplits: 1)
        if parts.count == 2 {
            result[parts[0].trimmingCharacters(in: .whitespaces)] =
                parts[1].trimmingCharacters(in: .whitespaces)
        }
    }
    return result
}

private struct InstalledRoute {
    let route: VPNRoute
    let interface: String
    let gateway: String?
    var scope: String? = nil

    var selection: [String] { ["-" + route.kind] + (scope.map { ["-ifscope", $0] } ?? []) + [route.destination] }
    var nextHop: [String] { gateway.map { [$0] } ?? ["-interface", interface] }

    func current() throws -> [String: String] {
        try routeInfo(route.address, interface: scope)
    }

    func matches(_ info: [String: String]) -> Bool {
        guard info["interface"] == interface else { return false }
        if let gateway, info["gateway"] != gateway { return false }
        guard let destination = info["destination"],
              Self.expanded(destination) == route.address else { return false }
        if route.kind == "host" {
            let flags = info["flags"] ?? ""
            guard flags.contains("HOST") else { return false }
            if scope == nil { return true }
            return flags.contains("UP") && flags.contains("STATIC") && flags.contains("IFSCOPE")
                && !flags.contains("WASCLONED") && !flags.contains("REJECT") && !flags.contains("BLACKHOLE")
        }
        guard let prefix = Int(route.destination.split(separator: "/")[1]),
              let mask = info["mask"] else { return false }
        let bits = UInt32.max << (32 - prefix)
        if Self.expanded(mask) == nil, mask.hasPrefix("0x") {
            return UInt32(mask.dropFirst(2), radix: 16) == bits
        }
        return Self.expanded(mask).flatMap(VPNRoute.ipv4) == bits
    }

    private static func expanded(_ value: String) -> String? {
        let octets = value.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(octets.count), octets.allSatisfy({ UInt8($0) != nil }) else { return nil }
        return (octets.map(String.init) + Array(repeating: "0", count: 4 - octets.count)).joined(separator: ".")
    }
}

private func routeInfo(_ address: String, interface: String? = nil) throws -> [String: String] {
    let scope = interface.map { ["-ifscope", $0] } ?? []
    return fields(try capture(routePath, ["-n", "get", "-inet"] + scope + [address]).text)
}

private struct IPv6RejectRoute {
    let network: String

    var arguments: [String] { ["-inet6", "-net", network, "-prefixlen", "1", "::1", "-reject"] }

    func isInstalled() throws -> Bool {
        try routeTable("inet6").contains { columns in
            columns[0] == "\(network)/1" && columns[1] == "::1" && columns[2].contains("R") && columns[3] == "lo0"
        }
    }
}

private func routeTable(_ family: String) throws -> [[Substring]] {
    let table = try capture("/usr/sbin/netstat", ["-rn", "-f", family])
    guard table.status == 0 else { throw Failure(L("Не удалось прочитать таблицу маршрутов \(family).")) }
    return table.text.split(separator: "\n").map { $0.split(whereSeparator: \.isWhitespace) }
        .filter { $0.count >= 4 }
}

private func isUsableGlobalDefault(_ columns: [Substring]) -> Bool {
    columns[0] == "default" && columns[2].contains("U")
        && !columns[2].contains("I") && !columns[2].contains("R") && !columns[2].contains("B")
}

private func waitForPrimaryIPv4(_ interface: String, stop: StopSignal) throws {
    let key = "State:/Network/Global/IPv4" as CFString
    var selected: String?
    for _ in 0..<32 {
        try stop.check()
        let settings = SCDynamicStoreCopyValue(nil, key) as? [String: Any]
        selected = settings?[kSCDynamicStorePropNetPrimaryInterface as String] as? String
        if selected == interface, try routeTable("inet").contains(where: {
            isUsableGlobalDefault($0) && $0[3] == interface
        }) { return }
        usleep(125_000)
    }
    throw Failure(L("macOS не выбрала \(interface) основным интерфейсом IPv4 (текущий: \(selected ?? L("не найден")))."))
}

private func isTunnel(_ name: String) -> Bool {
    ["utun", "ppp", "ipsec", "tun", "tap"].contains(where: name.hasPrefix)
}

private func physical(_ name: String) -> Bool {
    !name.isEmpty && !isTunnel(name) && !["lo", "gif", "stf"].contains(where: name.hasPrefix)
}

private func resolve(_ server: String) throws -> [String] {
    if VPNRoute.ipv4(server) != nil { return [server] }
    let result = try capture("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", server])
    var addresses: [String] = []
    for line in result.text.components(separatedBy: .newlines) {
        guard line.hasPrefix("ip_address:") else { continue }
        let ip = line.dropFirst("ip_address:".count).trimmingCharacters(in: .whitespaces)
        if VPNRoute.ipv4(ip) != nil, !addresses.contains(ip) { addresses.append(ip) }
    }
    guard !addresses.isEmpty else { throw Failure(L("DNS не вернул IPv4-адрес для \(server).")) }
    return addresses
}

private func physicalGateway() throws -> (gateway: String, interface: String)? {
    for columns in try routeTable("inet") {
        if columns[0] == "default", VPNRoute.ipv4(String(columns[1])) != nil,
           columns[1] != "0.0.0.0", physical(String(columns[3])) {
            return (String(columns[1]), String(columns[3]))
        }
    }
    return nil
}

private func add(_ rule: InstalledRoute, to owned: inout [InstalledRoute]) throws {
    let result = try capture(routePath, ["-n", "add", "-inet"] + rule.selection + rule.nextHop)
    if result.status == 0 {
        owned.append(rule)
        let scopeDescription = rule.scope.map { " (\($0))" } ?? ""
        emit("log", "\(rule.route.description) → \(rule.gateway ?? rule.interface)\(scopeDescription)")
    } else if rule.matches(try rule.current()) {
        emit("log", L("\(rule.route.description) → \(rule.interface) · маршрут уже есть"))
    } else {
        throw Failure(L("Не удалось добавить \(rule.route.description): \(result.text.trimmingCharacters(in: .whitespacesAndNewlines))"))
    }
}

private func verifyTransportRoute(_ route: InstalledRoute) throws {
    let info = try route.current()
    guard route.matches(info) else {
        let observed = [info["destination"], info["interface"], info["flags"]].compactMap { $0 }.joined(separator: " ")
        let details = observed.isEmpty ? L("маршрут отсутствует") : observed
        throw Failure(L("Маршрут до VPN-сервера \(route.route.address) через \(route.interface) не подтверждён (\(details))."))
    }
}

private func pinTransportRoute(to address: String, interface: String, owned: inout [InstalledRoute]) throws -> InstalledRoute {
    let info = try routeInfo(address, interface: interface)
    let flags = info["flags"] ?? ""
    guard info["interface"] == interface, flags.contains("UP"),
          !flags.contains("REJECT"), !flags.contains("BLACKHOLE") else {
        throw Failure(L("VPN-сервер \(address) недоступен через \(interface)."))
    }
    var gateway: String?
    if flags.contains("GATEWAY") {
        guard let address = info["gateway"], VPNRoute.ipv4(address).map({ $0 != 0 }) == true else {
            throw Failure(L("Не найден IPv4-узел для маршрута через \(interface)."))
        }
        gateway = address
    }
    let endpoint = InstalledRoute(route: VPNRoute(kind: "host", destination: address),
                                  interface: interface, gateway: gateway, scope: interface)
    if !endpoint.matches(info) {
        try add(endpoint, to: &owned)
        try verifyTransportRoute(endpoint)
    }
    return endpoint
}

private func currentPPP(_ name: String) -> String? {
    let dir = "/var/run"
    guard let link = try? String(contentsOfFile: "\(dir)/ppp-\(name).pid", encoding: .utf8),
          let pid = link.split(whereSeparator: \.isWhitespace).first.flatMap({ Int32($0) }),
          pid > 1, let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return nil }
    for file in files where file.range(of: #"^ppp[0-9]+\.pid$"#, options: .regularExpression) != nil {
        guard let record = try? String(contentsOfFile: "\(dir)/\(file)", encoding: .utf8),
              record.split(whereSeparator: \.isWhitespace).first.flatMap({ Int32($0) }) == pid else { continue }
        let interface = String(file.dropLast(4))
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let list else { return nil }
        defer { freeifaddrs(list) }
        var next: UnsafeMutablePointer<ifaddrs>? = list
        while let entry = next {
            let address = entry.pointee
            if String(cString: address.ifa_name) == interface,
               address.ifa_addr?.pointee.sa_family == UInt8(AF_INET),
               address.ifa_flags & UInt32(IFF_UP) != 0 { return interface }
            next = address.ifa_next
        }
    }
    return nil
}

private func preparePPPOptions() throws {
    try FileManager.default.createDirectory(atPath: "/etc/ppp", withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o755])
    let fd = open("/etc/ppp/options", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o644)
    if fd >= 0 { close(fd); return }
    if errno != EEXIST { throw Failure(L("Не удалось подготовить /etc/ppp/options для pppd.")) }
}

private final class PeerDNS {
    private let lock = NSLock()
    private var addresses: [String: String] = [:]

    func observe(_ message: String) {
        // macOS pppd reports negotiated DNS addresses on its log descriptor.
        let fields = message.split(whereSeparator: \.isWhitespace).suffix(5)
        guard fields.count == 5 else { return }
        let words = Array(fields)
        guard words[0] == ":", words[2] == "DNS", words[3] == "address",
              words[1] == "primary" || words[1] == "secondary",
              let ip = VPNRoute.ipv4(String(words[4])), ip != 0 else { return }
        lock.lock()
        defer { lock.unlock() }
        addresses[String(words[1])] = String(words[4])
    }

    var servers: [String] {
        lock.lock()
        defer { lock.unlock() }
        let primary = addresses["primary"]
        return [primary, addresses["secondary"]].compactMap { $0 }.reduce(into: []) {
            if !$0.contains($1) { $0.append($1) }
        }
    }
}

private func installDNSRule(_ rule: DNSRule, search: Bool, key: CFString) throws -> SCDynamicStore {
    guard let store = SCDynamicStoreCreate(nil, "SSTP VPN DNS" as CFString, nil, nil) else {
        throw Failure(L("Не удалось открыть DNS-настройки macOS."))
    }
    var settings: [String: Any] = [
        kSCPropNetDNSServerAddresses as String: rule.servers,
        kSCPropNetDNSSupplementalMatchDomains as String: [rule.suffix],
    ]
    if search {
        settings[kSCPropNetDNSSearchDomains as String] = [rule.suffix]
    } else {
        // configd otherwise adds supplemental domains to the search list.
        settings["SupplementalMatchDomainsNoSearch"] = 1
    }
    guard SCDynamicStoreAddTemporaryValue(store, key, settings as CFDictionary) else {
        throw Failure(L("macOS отклонила временные DNS-настройки (\(SCError()))."))
    }
    return store
}

private func redirectLogs(_ pipe: Pipe, password: String, login: String, dns: PeerDNS?,
                          trace: ConnectionTrace) -> DispatchGroup {
    let drained = DispatchGroup()
    let reader = pipe.fileHandleForReading
    DispatchQueue.global(qos: .utility).async(group: drained) {
        defer { try? reader.close() }
        var pending = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(reader.fileDescriptor, bytes.baseAddress, bytes.count)
            }
            if count == -1 && errno == EINTR { continue }
            guard count > 0 else { break }
            pending.append(contentsOf: buffer.prefix(count))
            while let end = pending.firstIndex(of: 10) {
                let message = String(decoding: pending[..<end], as: UTF8.self)
                    .replacingOccurrences(of: "\0", with: "")
                dns?.observe(message)
                let redacted = message
                    .replacingOccurrences(of: password, with: "••••")
                    .replacingOccurrences(of: login, with: "••••")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !redacted.isEmpty { trace.engine(redacted) }
                pending.removeSubrange(...end)
            }
            if pending.count > 32_768 { pending.removeAll() }
        }
    }
    return drained
}

private func run(_ request: VPNRequest, stop: StopSignal) throws {
    let trace = ConnectionTrace { emit("log", $0) }
    let routes = try request.validate()
    let suffix = try request.profile.dnsSuffix.map(Profile.normalizedDNSSuffix)
    var dnsRules = try request.profile.validatedDNSRules()
    let peerSuffix = suffix.flatMap { suffix in
        dnsRules.contains(where: { $0.suffix == suffix }) ? nil : suffix
    }
    let fullTunnel = request.profile.fullTunnel == true
    let requestPeerDNS = fullTunnel || peerSuffix != nil || dnsRules.isEmpty
    guard let executable = Engine.executable else {
        throw Failure(L("В приложении отсутствует сетевой компонент sstpc."))
    }
    if request.profile.trustMode == .custom, try !Certificates.parse(request.certificates).allSatisfy(\.current) {
        throw Failure(L("Замените сертификаты с истёкшим или ещё не начавшимся сроком действия."))
    }
    let lock = open("/var/run/ru.sstpgui.mac.lock", O_CREAT | O_NOFOLLOW | O_RDWR | O_CLOEXEC, 0o600)
    guard lock >= 0 else { throw Failure(L("Не удалось создать блокировку VPN в /var/run.")) }
    defer { close(lock) }
    guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw Failure(L("Клиент SSTP уже подключается или работает.")) }

    let defaults = fullTunnel
        ? try routeTable("inet") + routeTable("inet6")
        : ((try? routeTable("inet")) ?? []) + ((try? routeTable("inet6")) ?? [])
    if let other = defaults.first(where: { isUsableGlobalDefault($0) && isTunnel(String($0[3])) }) {
        let message = L("Обнаружен общий маршрут по умолчанию через туннель \(other[3]) (\(other[2])).")
        if fullTunnel { throw Failure(message + L(" Отключите его перед включением полного режима.")) }
        emit("log", message)
    }

    let process = Process()
    var logDrain: DispatchGroup?
    let dns = peerSuffix.map { _ in PeerDNS() }
    var dnsStores: [(store: SCDynamicStore, key: CFString)] = []
    var owned: [InstalledRoute] = []
    var ipv6Guards: [IPv6RejectRoute] = []
    var tunnel = ""
    var directoryTemplate = Array("/private/var/run/sstpgui.XXXXXXXX".utf8CString)
    guard let directory = directoryTemplate.withUnsafeMutableBufferPointer({ buffer in
        mkdtemp(buffer.baseAddress!).map { String(cString: $0) }
    }) else { throw Failure(L("Не удалось создать временную папку для сертификатов.")) }
    let bundle = URL(fileURLWithPath: directory).appendingPathComponent("ca.pem")
    defer {
        for entry in dnsStores {
            SCDynamicStoreRemoveValue(entry.store, entry.key)
        }
        for guardRoute in ipv6Guards.reversed() {
            do {
                if try guardRoute.isInstalled() {
                    let deleted = try capture(routePath, ["-n", "delete"] + guardRoute.arguments)
                    if deleted.status != 0 { throw Failure(deleted.text.trimmingCharacters(in: .whitespacesAndNewlines)) }
                }
            } catch {
                emit("log", L("Не удалось восстановить маршрут IPv6 \(guardRoute.network)/1: \(error.localizedDescription)"))
            }
        }
        for rule in owned.reversed() {
            do {
                // The kernel also removes interface routes when the PPP interface goes away.
                if rule.scope != nil || rule.gateway != nil {
                    guard rule.matches(try rule.current()) else { continue }
                } else {
                    guard if_nametoindex(rule.interface) != 0 else { continue }
                }
                let deleted = try capture(routePath, ["-n", "delete", "-inet"] + rule.selection + rule.nextHop)
                if deleted.status != 0, rule.matches(try rule.current()) {
                    emit("log", L("Не удалось удалить \(rule.route.description): \(deleted.text.trimmingCharacters(in: .whitespacesAndNewlines))"))
                }
            } catch {
                emit("log", L("Не удалось проверить маршрут \(rule.route.description)."))
            }
        }
        if process.isRunning {
            process.terminate()
            for _ in 0..<25 {
                if !process.isRunning { break }
                usleep(100_000)
            }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
        }
        _ = logDrain?.wait(timeout: .now() + .milliseconds(750))
        try? FileManager.default.removeItem(atPath: directory)
    }

    try stop.check()
    if request.profile.trustMode == .custom {
        try request.certificates.write(to: bundle, options: .atomic)
    }
    let jail = URL(fileURLWithPath: directory, isDirectory: true).appendingPathComponent("jail", isDirectory: true)
    try FileManager.default.createDirectory(at: jail, withIntermediateDirectories: false,
                                            attributes: [.posixPermissions: 0o755])
    try preparePPPOptions()

    let profile = request.profile
    let systemRoute = profile.usesSystemRouteForServer
    let overrideIPv4 = try profile.transportIPv4()
    trace.event("L7 DNS", overrideIPv4 == nil ? L("Разрешение имени \(profile.server).") : L("Используется заданный IPv4."), next: .dns)
    let ips = try overrideIPv4.map { [$0] } ?? resolve(profile.server)
    let gateway = systemRoute || fullTunnel ? nil : try physicalGateway()
    let transportRoute: InstalledRoute?
    trace.event("L7 DNS", "\(profile.server):\(profile.port) · \(ips.joined(separator: ", ")).", next: .route)
    if fullTunnel {
        let ip = ips[0]
        guard !routes.contains(where: { $0.kind == "host" && $0.contains(ip) }) else {
            throw Failure(L("Маршрут host \(ip) совпадает с адресом VPN-сервера."))
        }
        let routeInterface = try routeInfo(ip)["interface"] ?? ""
        let interface = physical(routeInterface) ? routeInterface : try physicalGateway()?.interface
        guard let interface else { throw Failure(L("Не найден обычный сетевой маршрут до \(ip).")) }
        transportRoute = try pinTransportRoute(to: ip, interface: interface, owned: &owned)
        trace.event("L3 IPv4", L("Маршрут до VPN-сервера через \(interface)."))
    } else {
        transportRoute = nil
    }
    for ip in fullTunnel ? [] : ips {
        try stop.check()
        if systemRoute {
            guard !routes.contains(where: { $0.contains(ip) }) else {
                throw Failure(L("Маршрут через SSTP перекрывает адрес VPN-сервера \(ip)."))
            }
            let interface = try routeInfo(ip)["interface"]
            trace.event("L3 IPv4", L("Маршрут до \(ip) · системный\(interface.map { " (\($0))" } ?? "")."))
            continue
        }
        if routes.contains(where: { $0.kind == "host" && $0.contains(ip) }) {
            throw Failure(L("Маршрут host \(ip) совпадает с адресом VPN-сервера."))
        }
        let info = try routeInfo(ip)
        let nic = info["interface"] ?? ""
        if physical(nic) {
            if info["destination"] == ip && info["flags"]?.contains("HOST") == true { continue }
            if let via = info["gateway"], VPNRoute.ipv4(via) != nil, via != "0.0.0.0" {
                try add(InstalledRoute(route: VPNRoute(kind: "host", destination: ip), interface: nic, gateway: via),
                        to: &owned)
            } else if routes.contains(where: { $0.contains(ip) }) {
                try add(InstalledRoute(route: VPNRoute(kind: "host", destination: ip), interface: nic, gateway: nil),
                        to: &owned)
            }
        } else if let gateway {
            try add(InstalledRoute(route: VPNRoute(kind: "host", destination: ip),
                                   interface: gateway.interface, gateway: gateway.gateway), to: &owned)
        } else {
            throw Failure(L("Не найден обычный сетевой маршрут до \(ip)."))
        }
    }

    try stop.check()
    let link = "sstpgui-" + UUID().uuidString.lowercased()
    let logs = Pipe()
    let passwordPipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    var environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
                       "SSTP_OPTIONS_DIR": directory, "SSTP_PASSWORD_STDIN": "1"]
    if let transportRoute { environment["SSTP_BIND_INTERFACE"] = transportRoute.interface }
    process.environment = environment
    process.currentDirectoryURL = URL(fileURLWithPath: directory)
    process.standardInput = passwordPipe
    process.standardOutput = logs
    process.standardError = logs
    let cAs = profile.trustMode == .custom ? ["--ca-cert", bundle.path] : []
    let fixedAddress = fullTunnel ? ips[0] : overrideIPv4
    let target = fixedAddress ?? profile.server
    let host = fixedAddress == nil ? [] : ["--host", profile.server]
    var arguments = cAs + host + [
        "--user", profile.login, "--priv-dir", jail.path,
        "--log-stderr", "--log-level", "3", "--tls-ext", "\(target):\(profile.port)",
        "linkname", link, "nodetach", "logfd", "2", fullTunnel ? "defaultroute" : "nodefaultroute",
        "noauth", "mtu", "1400", "mru", "1400",
    ]
    arguments += profile.authenticationOptions
    if let idle = profile.idleDisconnectSeconds, idle > 0 { arguments += ["idle", String(idle)] }
    if requestPeerDNS { arguments.append("usepeerdns") }
    arguments += profile.pppEncryption?.options ?? []
    process.arguments = arguments
    trace.event("L4 TCP", L("Начинается соединение с \(target):\(profile.port)."), next: .tcp)
    trace.event("TLS", L("Проверка сертификата · \(profile.trustMode.title)."))
    trace.event("L2 PPP", L("Методы аутентификации · \(profile.authentication.map(\.title).joined(separator: ", "))."))
    try passwordPipe.fileHandleForWriting.write(contentsOf: Data((request.password + "\n").utf8))
    try passwordPipe.fileHandleForWriting.close()
    try process.run()
    logDrain = redirectLogs(logs, password: request.password, login: profile.login, dns: dns, trace: trace)
    for _ in 0..<180 {
        try stop.check()
        guard process.isRunning else {
            _ = logDrain?.wait(timeout: .now() + .milliseconds(350))
            throw Failure(trace.exitMessage(process.terminationStatus))
        }
        if let found = currentPPP(link) {
            tunnel = found
            break
        }
        usleep(250_000)
    }
    guard !tunnel.isEmpty else {
        throw Failure(L("Интерфейс PPP не получил IPv4 за 45 секунд. Этап: \(trace.pendingLabel)."))
    }
    trace.event("L3 IPv4", L("\(tunnel) получил IPv4. Настройка маршрутов и DNS."), next: .routing)

    if fullTunnel {
        try waitForPrimaryIPv4(tunnel, stop: stop)
        for rule in [IPv6RejectRoute(network: "::"), IPv6RejectRoute(network: "8000::")] {
            try stop.check()
            let result = try capture(routePath, ["-n", "add"] + rule.arguments)
            guard result.status == 0 else {
                if try rule.isInstalled() { continue }
                throw Failure(L("Не удалось заблокировать обычный маршрут IPv6: \(result.text.trimmingCharacters(in: .whitespacesAndNewlines))"))
            }
            ipv6Guards.append(rule)
        }
        emit("log", L("Полный режим IPv4. Обычные маршруты IPv6 временно заблокированы."))
    }
    for route in routes {
        try stop.check()
        try add(InstalledRoute(route: route, interface: tunnel, gateway: nil), to: &owned)
    }
    if let transportRoute {
        try verifyTransportRoute(transportRoute)
        trace.event("L3 IPv4", L("Основной интерфейс IPv4 macOS · \(tunnel)."))
    }
    if let peerSuffix, let dns {
        for _ in 0..<10 {
            try stop.check()
            if dns.servers.count == 2 || !process.isRunning { break }
            usleep(100_000)
        }
        do {
            let servers = dns.servers
            guard !servers.isEmpty else { throw Failure(L("VPN-сервер не передал адреса DNS.")) }
            dnsRules.append(try DNSRule(suffix: peerSuffix, servers: servers))
        } catch {
            emit("log", L("Не удалось применить DNS-суффикс \(peerSuffix). \(error.localizedDescription)"))
        }
    }
    for rule in dnsRules {
        try stop.check()
        do {
            for server in rule.servers {
                try stop.check()
                if ips.contains(server) { throw Failure(L("Адрес DNS совпал с адресом VPN-сервера.")) }
                if try routeInfo(server)["interface"] != tunnel {
                    try add(InstalledRoute(route: VPNRoute(kind: "host", destination: server), interface: tunnel, gateway: nil),
                            to: &owned)
                }
            }
            let key = "State:/Network/Service/\(UUID().uuidString)/DNS" as CFString
            let store = try installDNSRule(rule, search: rule.suffix == suffix, key: key)
            dnsStores.append((store, key))
            trace.event("L7 DNS", L("DNS-суффикс \(rule.suffix) · \(rule.servers.joined(separator: ", "))."))
        } catch {
            emit("log", L("Не удалось применить DNS-суффикс \(rule.suffix). \(error.localizedDescription)"))
        }
    }
    try stop.check()
    guard process.isRunning else { throw Failure(L("VPN-соединение завершилось (код \(process.terminationStatus)).")) }
    trace.event("VPN", L("Маршруты установлены."), next: .connected)
    emit("connected", tunnel)
    if fullTunnel && profile.diagnoseInternet == true {
        do {
            let path = try routeInfo("1.1.1.1")["interface"] ?? L("не найден")
            trace.event("L3 IPv4", L("Системный маршрут до 1.1.1.1 · \(path), интерфейс SSTP · \(tunnel)."))
            try InternetDiagnostics.run(interface: tunnel, directory: directory,
                                        stopped: { stop.requested || !process.isRunning }, trace: trace)
        } catch is CancellationError {
            try stop.check()
        } catch {
            trace.event(L("Проверка"), L("Не удалось завершить тест интернет-трафика: \(error.localizedDescription)"))
        }
    }
    while process.isRunning {
        try stop.check()
        usleep(250_000)
    }
    try stop.check()
    throw Failure(L("VPN-соединение завершилось (код \(process.terminationStatus)). Этап: \(trace.pendingLabel)."))
}

@main
struct Helper {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        do {
            guard geteuid() == 0 else { throw Failure(L("Для VPN требуется разрешение администратора macOS.")) }
            // macOS pppd opens the private options file under its real UID.
            // Match sudo's root identity before launching sstpc and pppd.
            guard setgid(0) == 0, setuid(0) == 0,
                  getuid() == 0, geteuid() == 0, getgid() == 0, getegid() == 0 else {
                throw Failure(L("Не удалось подготовить права администратора для pppd."))
            }
            guard let line = readLine(), line.utf8.count <= 400 * 1024 else {
                throw Failure(L("Не удалось прочитать настройки VPN."))
            }
            let request = try JSONDecoder().decode(VPNRequest.self, from: Data(line.utf8))
            if let language = request.language { L10n.use(language) }
            let stop = StopSignal()
            DispatchQueue.global(qos: .userInitiated).async {
                _ = readLine()
                stop.request()
            }
            for number in [SIGTERM, SIGINT, SIGHUP] { signal(number) { _ in } }
            let signals = [SIGTERM, SIGINT, SIGHUP].map { number in
                let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
                source.setEventHandler { stop.request() }
                source.resume()
                return source
            }
            try withExtendedLifetime(signals) { try run(request, stop: stop) }
        } catch is CancellationError {
            emit("log", L("VPN отключён."))
        } catch {
            emit("error", error.localizedDescription)
        }
        emit("finished", "")
    }
}
