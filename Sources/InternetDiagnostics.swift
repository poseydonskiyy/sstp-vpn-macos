import Foundation

enum InternetDiagnostics {
    private static let name = "cloudflare-dns.com"
    private static let address = "1.1.1.1"
    private static let url = "https://cloudflare-dns.com/cdn-cgi/trace"
    private static let marker = "__SSTP_CHECK__"

    static func run(interface: String, directory: String, stopped: () -> Bool, trace: ConnectionTrace) throws {
        trace.event("Проверка", "Тестовый HTTPS к \(name). DNS и трафик проверяются отдельно.")

        let lookup = try run("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", name],
                             limit: 3, stopped: stopped)
        let addresses = lookup.output.split(separator: "\n").compactMap { line -> String? in
            guard line.hasPrefix("ip_address:") else { return nil }
            let value = line.dropFirst("ip_address:".count).trimmingCharacters(in: .whitespaces)
            return VPNRoute.ipv4(value) == nil ? nil : value
        }
        trace.event("L7 DNS", addresses.isEmpty
                    ? "Системный резолвер не вернул IPv4 для \(name) (код \(lookup.status))."
                    : "Системный резолвер: \(name) → \(addresses.joined(separator: ", ")).")

        let port = Int.random(in: 49152...63000)
        let path = URL(fileURLWithPath: directory, isDirectory: true).appendingPathComponent("tcp-diagnostic.txt")
        try Data().write(to: path)
        let log = try FileHandle(forWritingTo: path)
        defer { try? log.close() }
        let filter = "ip and tcp and host \(address) and port 443 and port \(port) and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)"
        let capture = command("/usr/sbin/tcpdump", ["-nn", "-l", "-s", "96", "-c", "12", "-i", interface, filter])
        capture.standardOutput = log
        capture.standardError = log
        var captureStarted = false
        do {
            try capture.run()
            captureStarted = true
        } catch {
            trace.event("L4 TCP", "Захват заголовков недоступен.")
        }
        defer { if captureStarted { finish(capture) } }
        var ready = false
        if captureStarted {
            for _ in 0..<12 {
                if stopped() { throw CancellationError() }
                if try read(path).contains("listening on ") {
                    ready = true
                    break
                }
                if !capture.isRunning { break }
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        let direct = try https(["--interface", interface, "--local-port", String(port),
                                "--resolve", "\(name):443:\(address)"], stopped: stopped)
        if captureStarted {
            finish(capture)
            captureStarted = false
            let output = try read(path)
            if ready || output.contains("listening on ") {
                let packets = packetCounts(output)
                trace.event("L4 TCP", "\(interface), \(address):443 · SYN \(packets.syn), SYN‑ACK \(packets.ack), RST \(packets.reset).")
            } else {
                trace.event("L4 TCP", "Захват на \(interface) не запустился. Счётчики SYN и SYN‑ACK недоступны.")
            }
        }
        report(direct, label: "\(interface) напрямую к \(address)", trace: trace)
        let system = try https([], stopped: stopped)
        report(system, label: "системный маршрут к \(name)", trace: trace)
    }

    static func packetCounts(_ output: String) -> (syn: Int, ack: Int, reset: Int) {
        var syn = 0, ack = 0, reset = 0
        for line in output.split(separator: "\n") {
            guard let start = line.range(of: "Flags ["), let end = line[start.upperBound...].firstIndex(of: "]") else { continue }
            let flags = line[start.upperBound..<end]
            if flags.contains("R") { reset += 1 }
            else if flags.contains("S") && flags.contains(".") { ack += 1 }
            else if flags.contains("S") { syn += 1 }
        }
        return (syn, ack, reset)
    }

    private static func https(_ route: [String], stopped: () -> Bool) throws -> (status: Int32, output: String) {
        let format = "\n\(marker) %{time_namelookup} %{time_connect} %{time_appconnect} %{http_code} %{local_ip} %{remote_ip}\n"
        return try run("/usr/bin/curl",
                       ["-q", "-4", "--silent", "--noproxy", "*", "--connect-timeout", "4", "--max-time", "6",
                        "--max-filesize", "4096", "--write-out", format] + route + [url],
                       limit: 7, stopped: stopped)
    }

    static func report(_ probe: (status: Int32, output: String), label: String, trace: ConnectionTrace) {
        let lines = probe.output.split(separator: "\n")
        guard let metrics = lines.last(where: { $0.hasPrefix(marker + " ") })?.split(separator: " "),
              metrics.count >= 5, let connect = Double(metrics[2]), let tls = Double(metrics[3]) else {
            trace.event("Проверка", "\(label) · нет результата curl (код \(probe.status)).")
            return
        }
        if probe.status == 6 {
            trace.event("L7 DNS", "\(label) · имя не разрешилось.")
            return
        }
        guard connect > 0 else {
            trace.event("L4 TCP", "\(label) · TCP не установлено (curl \(probe.status)).")
            return
        }
        let endpoints = metrics.count >= 7 ? " · \(metrics[5]) → \(metrics[6])" : ""
        trace.event("L4 TCP", "\(label) · \(milliseconds(connect)) мс\(endpoints).")
        guard tls >= connect && tls > 0 else {
            trace.event("TLS", "\(label) · рукопожатие не завершилось (curl \(probe.status)).")
            return
        }
        trace.event("TLS", "\(label) · \(milliseconds(tls - connect)) мс после TCP.")
        let status = metrics[4]
        let publicIP = lines.first(where: { line in
            line.hasPrefix("ip=") && VPNRoute.ipv4(String(line.dropFirst(3))) != nil
        }).map { " · внешний IPv4 \($0.dropFirst(3))" } ?? ""
        if status == "000" {
            trace.event("L7 HTTP", "\(label) · ответа нет (curl \(probe.status)).")
        } else {
            let result = probe.status == 0 ? "" : " · curl \(probe.status)"
            trace.event("L7 HTTP", "\(label) · HTTP \(status)\(publicIP)\(result).")
        }
    }

    private static func milliseconds(_ seconds: Double) -> String {
        String(format: "%.1f", seconds * 1_000)
    }

    private static func read(_ url: URL) throws -> String {
        String(decoding: try Data(contentsOf: url), as: UTF8.self)
    }

    private static func command(_ path: String, _ arguments: [String]) -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        return process
    }

    private static func finish(_ process: Process) {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }

    private static func run(_ path: String, _ arguments: [String], limit: TimeInterval,
                            stopped: () -> Bool) throws -> (status: Int32, output: String) {
        if stopped() { throw CancellationError() }
        let process = command(path, arguments)
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(limit)
        while process.isRunning && !stopped() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        finish(process)
        if stopped() { throw CancellationError() }
        return (process.terminationStatus, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }
}
