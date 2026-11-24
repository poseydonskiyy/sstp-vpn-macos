import Foundation

final class ConnectionTrace {
    enum Stage: Int {
        case preparation, dns, route, tcp, tls, http, sstp, ppp, authentication, ipcp, routing, connected

        var label: String {
            switch self {
            case .preparation: "подготовка"
            case .dns: "L7 DNS сервера"
            case .route: "L3 маршрут до сервера"
            case .tcp: "L4 TCP до сервера"
            case .tls: "TLS"
            case .http: "L7 HTTP для SSTP"
            case .sstp: "L7 согласование SSTP"
            case .ppp: "L2 согласование PPP"
            case .authentication: "L2 ожидание результата MS‑CHAPv2"
            case .ipcp: "L3 выдача IPv4 через IPCP"
            case .routing: "L3 установка маршрутов и DNS"
            case .connected: "передача трафика через VPN"
            }
        }
    }

    private let start = DispatchTime.now().uptimeNanoseconds
    private let lock = NSLock()
    private let write: (String) -> Void
    private var pending = Stage.preparation

    init(write: @escaping (String) -> Void) {
        self.write = write
    }

    var pendingLabel: String {
        lock.lock()
        defer { lock.unlock() }
        return pending.label
    }

    func event(_ layer: String, _ message: String, next: Stage? = nil) {
        lock.lock()
        defer { lock.unlock() }
        if let next, next.rawValue >= pending.rawValue { pending = next }
        let milliseconds = (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
        write("[+\(milliseconds) мс · \(layer)] \(message)")
    }

    func engine(_ message: String) {
        if message.contains("Resolved ") {
            event("L7 DNS", message)
        } else if message.contains("Connected to ") {
            event("L4 TCP", message, next: .tls)
        } else if message.contains("TCP ") || message.contains("SSTP transport socket bound")
                    || message.contains("Connection failed (") || message.contains("Connect timed out") {
            event("L4 TCP", message)
        } else if message.contains("TLS handshake established") {
            event("TLS", message, next: .http)
        } else if message.contains("TLS") {
            event("TLS", message)
        } else if message.contains("SSTP HTTP handshake accepted") {
            event("L7 HTTP", message, next: .sstp)
        } else if message.contains("HTTP handshake") {
            event("L7 HTTP", message)
        } else if message.contains("Sending Connect-Request Message") || message.contains("Sending Connected Message")
                    || message.contains("Connection Established") {
            event("L7 SSTP", message)
        } else if message.contains("Started PPP Link Negotiation") {
            event("L7 SSTP", "Connect-ACK получен. Начинается PPP.", next: .ppp)
        } else if message.contains("CHAP Success") {
            event("L2 MS‑CHAPv2", message, next: .ipcp)
        } else if message.contains("CHAP Response") {
            event("L2 MS‑CHAPv2", message, next: .authentication)
        } else if message.contains("CHAP") {
            event("L2 MS‑CHAPv2", message)
        } else if message.contains("IPCP") || message.contains(" IP address ") {
            event("L3 IPCP", message)
        } else if message.contains(" DNS address ") {
            event("L7 DNS", message)
        } else if message.contains("PPP") || message.contains("LCP") || message.contains("ppp") {
            event("L2 PPP", message)
        } else {
            event("VPN", message)
        }
    }
}
