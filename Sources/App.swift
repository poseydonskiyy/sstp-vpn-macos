import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: VPNModel?

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        model?.requestQuit() ?? .terminateNow
    }
}

@main
struct SSTPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = VPNModel()

    var body: some Scene {
        Window("SSTP VPN", id: "main") {
            VPNWindow(model: model)
                .onAppear { delegate.model = model }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    model.refreshEngine()
                }
        }
        .defaultSize(width: 855, height: 595)
        .windowResizability(.contentMinSize)
    }
}

private enum Page: String, CaseIterable, Identifiable {
    case connection = "Подключение"
    case routes = "Маршруты"
    case certificates = "Сертификаты"
    case journal = "Журнал"

    var id: Self { self }
    var icon: String {
        switch self {
        case .connection: "shield.lefthalf.filled"
        case .routes: "point.topleft.down.to.point.bottomright.curvepath"
        case .certificates: "checkmark.seal"
        case .journal: "list.bullet.rectangle"
        }
    }
}

private let accent = Color(red: 0.15, green: 0.44, blue: 0.83)

struct VPNWindow: View {
    @ObservedObject var model: VPNModel
    @State private var page: Page = .connection
    @State private var windowsImport = false
    @State private var profileToDelete: SavedProfile?

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text(page.rawValue).font(.system(size: 28, weight: .semibold))
                    Spacer()
                    if page == .connection {
                        Button("Импорт PowerShell…") { windowsImport = true }
                        .fixedSize()
                        .disabled(model.busy)
                    }
                }
                .padding(.horizontal, 28)
                .padding(.vertical, 22)
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        switch page {
                        case .connection: connection
                        case .routes:
                            if model.library.selected != nil { RoutePage(model: model) }
                            else { noProfiles }
                        case .certificates:
                            if let selected = model.library.selected { certificates(for: selected) }
                            else { noProfiles }
                        case .journal: journal
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 28)
                    .padding(.bottom, 20)
                }
                Divider()
                footer
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(minWidth: 760, minHeight: 530)
        .tint(accent)
        .alert("SSTP VPN", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK", role: .cancel) { model.error = nil }
        } message: {
            Text(model.error ?? "")
        }
        .sheet(isPresented: $windowsImport) {
            WindowsImportSheet(model: model)
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 9) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 29, height: 29)
                    .accessibilityHidden(true)
                Text("SSTP VPN").font(.title3.weight(.semibold))
            }
            .padding(.horizontal, 10)
            .padding(.bottom, 20)
            ForEach(Page.allCases) { item in
                Button {
                    page = item
                    model.notice = nil
                } label: {
                    Label(item.rawValue, systemImage: item.icon)
                        .font(.system(size: 13, weight: page == item ? .semibold : .regular))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(page == item ? accent.opacity(0.13) : .clear, in: RoundedRectangle(cornerRadius: 7))
                        .foregroundStyle(page == item ? accent : .primary)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(page == item ? .isSelected : [])
            }
            Spacer()
            HStack(spacing: 6) {
                Image(systemName: model.engine == nil ? "exclamationmark.circle" : "checkmark.circle")
                Text(model.engine == nil ? "sstpc не найден" : "sstpc доступен")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 10)
        }
        .padding(14)
        .frame(width: 186)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var connection: some View {
        Group {
            if model.engine == nil {
                Panel {
                    Label("Сетевой компонент недоступен", systemImage: "exclamationmark.circle")
                        .font(.headline)
                    Text("Замените SSTP VPN.app копией из архива.")
                        .foregroundStyle(.secondary)
                }
            }
            if let selected = model.library.selected { profileEditor(for: selected) }
            else { noProfiles }
        }
    }

    private var noProfiles: some View {
        Panel {
            Text("Нет профилей").font(.headline)
            Button("Создать профиль") {
                model.createProfile()
                page = .connection
            }
        }
    }

    private func profileEditor(for selected: SavedProfile) -> some View {
        Panel {
            VStack(alignment: .leading, spacing: 13) {
                Picker("Профиль", selection: Binding(
                    get: { model.library.selected?.id ?? selected.id }, set: { model.selectProfile($0) }
                )) {
                    ForEach(model.library.profiles) { profile in
                        Text(profile.title).tag(profile.id)
                    }
                }
                HStack(alignment: .top, spacing: 12) {
                    Entry("Сервер") {
                        TextField("vpn.example.com", text: $model.profile.server)
                            .accessibilityLabel("Сервер")
                    }
                    Entry("Порт") {
                        TextField("443", text: $model.profile.port)
                            .accessibilityLabel("Порт")
                    }
                    .frame(width: 85)
                }
                if model.profile.fullTunnel != true {
                    DisclosureGroup("Маршрут до VPN-сервера") {
                        Toggle("Использовать системный маршрут", isOn: Binding(
                            get: { model.profile.useSystemRouteForServer == true },
                            set: { model.profile.useSystemRouteForServer = $0 }
                        ))
                        if model.profile.usesSystemRouteForServer {
                            Entry("IPv4 для подключения (необязательно)") {
                                TextField("По DNS", text: Binding(
                                    get: { model.profile.serverIPv4Override ?? "" },
                                    set: { model.profile.serverIPv4Override = $0 }
                                ))
                            }
                        }
                    }
                }
                Entry("Логин VPN") {
                    TextField("user@example.com", text: $model.profile.login)
                        .accessibilityLabel("Логин VPN")
                }
                Menu("Метод PPP · \(model.profile.authentication.map(\.title).joined(separator: ", "))") {
                    ForEach(PPPAuthentication.allCases) { method in
                        Toggle(method.title, isOn: Binding(
                            get: { model.profile.authentication.contains(method) },
                            set: { enabled in
                                var selected = Set(model.profile.authentication)
                                if enabled { selected.insert(method) } else { selected.remove(method) }
                                if !selected.isEmpty {
                                    model.profile.pppAuthentication = PPPAuthentication.allCases.filter { selected.contains($0) }
                                }
                            }
                        ))
                        .disabled(model.profile.authentication == [method])
                    }
                    Divider()
                    Picker("Шифрование внутри PPP", selection: Binding(
                        get: { model.profile.pppEncryption ?? .optional },
                        set: { model.profile.pppEncryption = $0 }
                    )) {
                        ForEach(PPPEncryption.allCases) { level in
                            Text(level.title).tag(level)
                        }
                    }
                }
                if let suffix = model.profile.dnsSuffix {
                    LabeledContent("DNS-суффикс", value: suffix)
                }
                ForEach(model.profile.dnsRules ?? [], id: \.suffix) { rule in
                    LabeledContent(rule.suffix, value: rule.servers.joined(separator: ", "))
                }
                Entry("Пароль VPN") {
                    SecureField("Введите пароль", text: $model.password)
                        .accessibilityLabel("Пароль VPN")
                }
                Toggle("Сохранять пароль в Связке ключей", isOn: Binding(
                    get: { model.profile.remember }, set: { model.setRemember($0) }
                ))
            }
            .textFieldStyle(.roundedBorder)
            .disabled(model.busy)
            HStack {
                Button("Сохранить профиль") { model.saveProfile() }
                .disabled(model.busy)
                if let notice = model.notice { Text(notice).font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button("Удалить профиль…", role: .destructive) { profileToDelete = selected }
                    .disabled(model.busy)
                    .confirmationDialog("Удалить профиль?", isPresented: Binding(
                        get: { profileToDelete != nil },
                        set: { if !$0 { profileToDelete = nil } }
                    ), titleVisibility: .visible, presenting: profileToDelete) { target in
                        Button("Удалить", role: .destructive) { model.deleteProfile(target.id) }
                        Button("Отмена", role: .cancel) {}
                    } message: { target in
                        Text("Профиль «\(target.name)», его маршруты и сохранённый пароль будут удалены.")
                    }
            }
        }
    }

    private func certificates(for selected: SavedProfile) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Panel {
                Text("Проверка сервера · \(selected.name)").font(.headline)
                Picker("Источник доверия", selection: Binding(
                    get: { model.profile.trustMode }, set: { model.setTrustMode($0) }
                )) {
                    ForEach(ServerTrustMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .disabled(model.busy)
                Text(model.profile.trustMode == .system
                     ? "macOS проверяет имя сервера и цепочку сертификатов при подключении."
                     : "Приложение проверяет имя сервера и использует корневые CA из общего комплекта.")
                    .foregroundStyle(.secondary)
            }
            if model.profile.trustMode == .custom { customCertificates }
        }
    }

    private var customCertificates: some View {
        Panel {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Общий комплект CA")
                        .font(.headline)
                    Text(model.customBundle
                         ? "Используется всеми профилями, в которых выбран этот источник доверия."
                         : "Добавьте корневой сертификат вашего центра сертификации.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Menu("Обновить CA…") {
                    Button("Добавить сертификаты…") { model.importCertificates(append: true) }
                    Button("Заменить весь комплект…") { model.importCertificates(append: false) }
                }
                .fixedSize()
                .disabled(model.busy)
            }
            if model.certificates.isEmpty {
                Text("Загрузите рабочий комплект сертификатов CA.").foregroundStyle(.secondary)
            }
            ForEach(model.certificates) { item in
                Divider()
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: item.current && !item.expiring ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(item.current && !item.expiring ? Color.green : Color.orange)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(item.subject).fontWeight(.medium)
                        Text(item.starts.formatted(date: .abbreviated, time: .omitted) + " — " +
                             item.expires.formatted(date: .abbreviated, time: .omitted))
                        .font(.caption).foregroundStyle(.secondary)
                        if !item.current {
                            Text("Вне срока действия").font(.caption).foregroundStyle(.red)
                        } else if item.expiring {
                            Text("Истекает в течение 30 дней").font(.caption).foregroundStyle(.orange)
                        }
                    }
                    Spacer(minLength: 0)
                    Button(role: .destructive) { model.removeCertificate(item) } label: {
                        Image(systemName: "trash")
                    }
                    .help("Удалить из общего комплекта")
                    .accessibilityLabel("Удалить \(item.subject)")
                    .disabled(model.busy || model.certificates.count <= 1)
                }
            }
            if let notice = model.notice { Text(notice).font(.caption).foregroundStyle(.secondary) }
        }
    }

    private var journal: some View {
        Panel {
            HStack {
                Text("События подключения").font(.headline)
                Spacer()
                Button("Скопировать") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.logs.joined(separator: "\n"), forType: .string)
                }.disabled(model.logs.isEmpty)
                Button("Очистить") { model.clearLog() }.disabled(model.logs.isEmpty)
            }
            if model.profile.fullTunnel == true && model.library.selected != nil {
                Toggle("Проверять интернет через Cloudflare после подключения", isOn: Binding(
                    get: { model.profile.diagnoseInternet == true },
                    set: { model.profile.diagnoseInternet = $0 }
                ))
                .disabled(model.busy)
            }
            if model.logs.isEmpty {
                Text("Записей пока нет.").foregroundStyle(.secondary).padding(.vertical, 20)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        Text(model.logs.joined(separator: "\n"))
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id("log")
                    }
                    .frame(height: 280)
                    .onAppear { proxy.scrollTo("log", anchor: .bottom) }
                    .onChange(of: model.logs.last) { _, _ in proxy.scrollTo("log", anchor: .bottom) }
                }
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 11) {
            if model.state == .connecting || model.state == .disconnecting {
                ProgressView().controlSize(.small)
            } else {
                Circle().fill(model.busy ? Color.green : Color.secondary.opacity(0.5)).frame(width: 9, height: 9)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(model.state.label).font(.headline)
                if case .connected(let interface) = model.state {
                    Text(interface).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button(model.busy ? (model.state == .connecting ? "Отменить" : "Отключить") : "Подключить") {
                if model.busy { model.disconnect() }
                else { model.connect() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.state == .disconnecting ||
                      (!model.busy && (model.engine == nil || model.library.selected == nil)))
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 14)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.65))
    }
}

private struct WindowsImportSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: VPNModel
    @State private var script = ""
    @State private var issue: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Импорт из Windows").font(.title2.bold())
            Text("Вставьте профиль SSTP, маршруты и DNS-правила PowerShell или откройте файл .ps1. Логин и пароль вводятся после импорта.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $script)
                .font(.system(.body, design: .monospaced))
                .accessibilityLabel("Команды PowerShell")
                .frame(minHeight: 195)
                .border(Color.secondary.opacity(0.3))
            if let issue {
                Text(issue).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Открыть файл…") {
                    do {
                        if let text = try model.openWindowsConfig() {
                            script = text
                            issue = nil
                        }
                    } catch { issue = error.localizedDescription }
                }
                Spacer()
                Button("Отмена", role: .cancel) { dismiss() }
                Button("Импортировать") {
                    do {
                        try model.importWindows(script)
                        dismiss()
                    } catch { issue = error.localizedDescription }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(script.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(22)
        .frame(width: 620, height: 360)
    }
}

private struct Entry<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content
    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.callout.weight(.medium))
            content
        }
    }
}

private struct Panel<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 13) { content }
            .padding(17)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.primary.opacity(0.1)))
    }
}

private struct RoutePage: View {
    @ObservedObject var model: VPNModel
    @State private var kind = "host"
    @State private var address = ""
    @State private var bulk = ""
    @State private var showBulk = false
    @State private var inputError: String?

    var body: some View {
        let routes = (try? VPNRoute.parse(model.profile.routes)) ?? []
        Panel {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Трафик через VPN").font(.headline)
                    Text("IPv4-адреса и подсети для текущего профиля.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Править списком…") {
                    bulk = model.profile.routes
                    inputError = nil
                    showBulk = true
                }
                .disabled(model.busy)
            }
            Toggle("Весь интернет-трафик IPv4 через VPN", isOn: Binding(
                get: { model.profile.fullTunnel == true }, set: { model.setFullTunnel($0) }
            ))
            .disabled(model.busy)
            if model.profile.fullTunnel == true {
                Text("На время подключения обычный выход по IPv6 блокируется. Для смены внешнего IP сервер должен выпускать трафик в интернет.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Picker("Тип маршрута", selection: $kind) {
                    Text("IP-адрес").tag("host")
                    Text("Подсеть").tag("net")
                }
                .labelsHidden()
                .frame(width: 113)
                TextField(kind == "host" ? "10.1.1.3" : "10.20.30.0/24", text: $address)
                    .accessibilityLabel("Адрес маршрута")
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { add(routes) }
                Button("Добавить") { add(routes) }.disabled(address.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .disabled(model.busy)
            Divider()
            if routes.isEmpty {
                Text("Список маршрутов пуст.").foregroundStyle(.secondary)
            }
            ForEach(routes, id: \.self) { route in
                HStack {
                    Image(systemName: route.kind == "host" ? "desktopcomputer" : "point.3.connected.trianglepath.dotted")
                        .frame(width: 22)
                        .foregroundStyle(.secondary)
                    Text(route.destination).font(.system(.body, design: .monospaced))
                    Text(route.kind == "host" ? "IP-адрес" : "Подсеть")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button(role: .destructive) {
                        save(routes.filter { $0 != route })
                    } label: {
                        Image(systemName: "trash")
                    }
                    .help("Удалить \(route.destination)")
                    .accessibilityLabel("Удалить \(route.destination)")
                    .disabled(model.busy)
                }
            }
        }
        .sheet(isPresented: $showBulk) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Список маршрутов IPv4").font(.title2.bold())
                Text("Один маршрут на строку. Форматы: host 10.1.1.3 и net 10.20.30.0/24.")
                    .foregroundStyle(.secondary)
                TextEditor(text: $bulk)
                    .font(.system(.body, design: .monospaced))
                    .accessibilityLabel("Список маршрутов")
                    .frame(height: 190)
                    .border(Color.secondary.opacity(0.3))
                if let inputError { Text(inputError).font(.callout).foregroundStyle(.red) }
                HStack {
                    Spacer()
                    Button("Отмена", role: .cancel) { showBulk = false }
                    Button("Сохранить") {
                        do {
                            try model.replaceRoutes(VPNRoute.parse(bulk))
                            showBulk = false
                        } catch { inputError = error.localizedDescription }
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(21)
            .frame(width: 540)
        }
    }

    private func add(_ routes: [VPNRoute]) {
        guard !model.busy else { return }
        do {
            let value = try VPNRoute.parse(kind + " " + address)
            guard value.count == 1 else { throw Failure("Укажите один адрес или одну подсеть.") }
            let updated = try VPNRoute.parse((routes + value).map(\.description).joined(separator: "\n"))
            try model.replaceRoutes(updated)
            address = ""
        } catch { model.error = error.localizedDescription }
    }

    private func save(_ routes: [VPNRoute]) {
        do { try model.replaceRoutes(routes) }
        catch { model.error = error.localizedDescription }
    }
}
