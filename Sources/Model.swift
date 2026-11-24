import AppKit
import Foundation
import UniformTypeIdentifiers

@MainActor
final class VPNModel: ObservableObject {
    enum State: Equatable {
        case disconnected, connecting, connected(String), disconnecting

        var label: String {
            switch self {
            case .disconnected: "Не подключено"
            case .connecting: "Подключение…"
            case .connected: "Подключено"
            case .disconnecting: "Отключение…"
            }
        }
    }

    @Published private(set) var library: ProfileLibrary
    @Published var profile: Profile
    @Published var password = ""
    @Published private(set) var state: State = .disconnected
    @Published private(set) var engine: String?
    @Published private(set) var certificates: [CertificateInfo] = []
    @Published private(set) var customBundle = false
    @Published private(set) var logs: [String] = []
    @Published var error: String?
    @Published var notice: String?
    private var session: PrivilegedSession?
    private var pendingQuit = false
    private var passwords: [String: String] = [:]

    var busy: Bool { state != .disconnected }

    init() {
        let library = Storage.load()
        self.library = library
        profile = library.selected?.settings ?? Profile()
        if let selected = library.selected, profile.remember { password = Storage.readPassword(selected.id) }
        refreshEngine()
        refreshCustomCertificates()
    }

    func refreshEngine() { engine = Engine.executable }

    func saveSettings() throws {
        guard let selected = library.selected else { return }
        var updated = library
        updated.update(profile, id: selected.id)
        try Storage.save(updated)
        library = updated
    }

    func saveProfile() {
        guard !busy, let selected = library.selected else { return }
        do {
            if profile.remember {
                try Storage.savePassword(password.isEmpty ? nil : password, for: selected.id)
            }
            try saveSettings()
            notice = "Профиль сохранён."
        } catch { self.error = error.localizedDescription }
    }

    func selectProfile(_ id: String) {
        guard !busy, let selected = library.selected, id != selected.id,
              library.profiles.contains(where: { $0.id == id }) else { return }
        var updated = library
        updated.update(profile, id: selected.id)
        updated.selectedID = id
        do {
            try activate(updated)
            notice = nil
        } catch { self.error = error.localizedDescription }
    }

    func createProfile() {
        guard !busy, library.profiles.isEmpty else { return }
        let starter = SavedProfile(id: UUID().uuidString, name: "Основной профиль", settings: Profile())
        do {
            try activate(ProfileLibrary(profiles: [starter], selectedID: starter.id))
            notice = nil
        } catch { self.error = error.localizedDescription }
    }

    func deleteProfile(_ id: String) {
        guard !busy, library.selected?.id == id else { return }
        var updated = library
        updated.remove(id)
        do { try activate(updated) }
        catch {
            self.error = error.localizedDescription
            return
        }
        notice = "Профиль удалён."
        var cleanupErrors: [String] = []
        do { try Storage.savePassword(nil, for: id) }
        catch { cleanupErrors.append("Не удалось удалить его пароль. \(error.localizedDescription)") }
        if id == ProfileLibrary.legacyID {
            do { try Storage.removeLegacySnapshot() }
            catch { cleanupErrors.append("Не удалось удалить прежнюю копию настроек. \(error.localizedDescription)") }
        }
        if !cleanupErrors.isEmpty {
            self.error = "Профиль удалён. " + cleanupErrors.joined(separator: "\n")
        }
    }

    func openWindowsConfig() throws -> String? {
        let panel = NSOpenPanel()
        panel.title = "Выберите скрипт настройки SSTP для Windows"
        panel.allowedContentTypes = [.plainText, UTType(filenameExtension: "ps1") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return try WindowsConfig.decode(Data(contentsOf: url))
    }

    func importWindows(_ text: String) throws {
        guard !busy else { return }
        let imported = try WindowsConfig.parse(text)
        var updated = library
        if let selected = library.selected { updated.update(profile, id: selected.id) }
        try updated.addWindows(imported)
        try activate(updated)
        let routes = try VPNRoute.parse(profile.routes).count
        notice = "Импортировано профилей: \(imported.count). Маршрутов в выбранном профиле: \(routes)."
    }

    private func activate(_ updated: ProfileLibrary) throws {
        try Storage.save(updated)
        if let previous = library.selected {
            passwords[previous.id] = updated.profiles.contains(where: { $0.id == previous.id }) ? password : nil
        }
        library = updated
        profile = updated.selected?.settings ?? Profile()
        password = updated.selected.map { passwords[$0.id] ?? (profile.remember ? Storage.readPassword($0.id) : "") } ?? ""
        refreshCustomCertificates()
    }

    func setRemember(_ value: Bool) {
        guard let selected = library.selected else { return }
        let previous = profile.remember
        profile.remember = value
        do {
            try Storage.savePassword(value && !password.isEmpty ? password : nil, for: selected.id)
            try saveSettings()
        } catch {
            profile.remember = previous
            self.error = error.localizedDescription
        }
    }

    func setTrustMode(_ mode: ServerTrustMode) {
        guard library.selected != nil else { return }
        let previous = profile.serverTrust
        profile.serverTrust = mode
        do { try saveSettings() }
        catch {
            profile.serverTrust = previous
            self.error = error.localizedDescription
            return
        }
        refreshCustomCertificates()
    }

    func setFullTunnel(_ enabled: Bool) {
        guard !busy, library.selected != nil else { return }
        let previous = profile.fullTunnel
        profile.fullTunnel = enabled
        do { try saveSettings() }
        catch {
            profile.fullTunnel = previous
            self.error = error.localizedDescription
        }
    }

    func connect() {
        guard !busy, let selected = library.selected else { return }
        do {
            refreshEngine()
            guard engine != nil else { throw Failure("В приложении отсутствует сетевой компонент sstpc.") }
            var bundle = Data()
            if profile.trustMode == .custom {
                try loadCustomCertificates()
                guard customBundle else {
                    throw Failure("Импортируйте комплект CA в разделе «Сертификаты» или выберите системное доверие macOS.")
                }
                let usableCA = certificates.filter(\.current)
                guard !usableCA.isEmpty else {
                    throw Failure("Проверьте сроки действия сертификатов в разделе «Сертификаты».")
                }
                bundle = Certificates.pem(usableCA)
            }
            let request = VPNRequest(profile: profile, password: password,
                                     certificates: bundle)
            _ = try request.validate()
            if profile.remember { try Storage.savePassword(password, for: selected.id) }
            try saveSettings()
            state = .connecting
            notice = nil
            log("Запрошено подключение к \(profile.server):\(profile.port).")
            let session = PrivilegedSession()
            self.session = session
            session.start(request) { [weak self] event in
                DispatchQueue.main.async { self?.receive(event) }
            }
        } catch { self.error = error.localizedDescription }
    }

    func disconnect() {
        guard busy, state != .disconnecting else { return }
        state = .disconnecting
        session?.stop()
    }

    func requestQuit() -> NSApplication.TerminateReply {
        guard busy else { return .terminateNow }
        pendingQuit = true
        disconnect()
        return .terminateLater
    }

    func importCertificates(append: Bool) {
        let panel = NSOpenPanel()
        panel.title = "Выберите новую цепочку или отдельные сертификаты CA"
        panel.allowsMultipleSelection = true
        guard panel.runModal() == .OK else { return }
        do {
            let imported = try panel.urls.flatMap { try Certificates.parse(Data(contentsOf: $0)) }
            guard imported.allSatisfy(\.current) else {
                throw Failure("В выбранном комплекте есть сертификаты вне срока действия.")
            }
            try saveCertificates((append ? certificates : []) + imported)
            notice = "Общий комплект CA обновлён."
        } catch { self.error = error.localizedDescription }
    }

    func removeCertificate(_ item: CertificateInfo) {
        guard certificates.count > 1 else { return }
        do {
            try saveCertificates(certificates.filter { $0.id != item.id })
            notice = "Сертификат удалён из общего комплекта."
        } catch { self.error = error.localizedDescription }
    }

    private func saveCertificates(_ group: [CertificateInfo]) throws {
        let parsed = try Certificates.parse(Certificates.pem(group))
        try Storage.prepare()
        try Certificates.pem(parsed).write(to: Storage.customCA, options: .atomic)
        certificates = parsed
        customBundle = true
    }

    func replaceRoutes(_ routes: [VPNRoute]) throws {
        guard let selected = library.selected else { return }
        var updated = library
        var settings = profile
        settings.routes = routes.map(\.description).joined(separator: "\n")
        updated.update(settings, id: selected.id)
        try Storage.save(updated)
        library = updated
        profile = settings
    }

    func clearLog() { logs.removeAll() }

    private func loadCustomCertificates() throws {
        customBundle = FileManager.default.fileExists(atPath: Storage.customCA.path)
        certificates = try customBundle
            ? Certificates.parse(Data(contentsOf: Storage.customCA))
            : []
    }

    private func refreshCustomCertificates() {
        guard profile.trustMode == .custom else { return }
        do { try loadCustomCertificates() }
        catch {
            certificates = []
            self.error = error.localizedDescription
        }
    }

    private func receive(_ event: VPNEvent) {
        switch event.type {
        case "connected":
            if state != .disconnecting { state = .connected(event.message) }
            log("VPN подключён · \(event.message).")
        case "log":
            log(event.message)
        case "error":
            error = event.message
            log(event.message)
        case "closed":
            session = nil
            state = .disconnected
            if pendingQuit { NSApp.reply(toApplicationShouldTerminate: true) }
        default:
            break
        }
    }

    private func log(_ message: String) {
        let time = Date().formatted(.dateTime.hour().minute().second())
        logs.append("[\(time)] \(message)")
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }
}
