import AppKit
import Foundation
import Security
import Darwin

final class PrivilegedSession {
    private let lock = NSLock()
    private var descriptor: Int32 = -1
    private var cancelled = false

    func start(_ request: VPNRequest, onEvent: @escaping (VPNEvent) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do { try self.run(request, onEvent: onEvent) }
            catch { onEvent(VPNEvent(type: "error", message: error.localizedDescription)) }
            onEvent(VPNEvent(type: "closed", message: ""))
        }
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        cancelled = true
        if descriptor >= 0 { _ = try? writeLine(Data("stop\n".utf8), to: descriptor) }
    }

    private func run(_ request: VPNRequest, onEvent: (VPNEvent) -> Void) throws {
        guard let helper = Bundle.main.url(forAuxiliaryExecutable: "sstp-network") else {
            throw Failure(L("Установочный пакет повреждён: отсутствует сетевой компонент."))
        }
        var auth: AuthorizationRef?
        let created = AuthorizationCreate(nil, nil, [], &auth)
        guard created == errAuthorizationSuccess, let auth else {
            throw Failure(L("Не удалось запросить разрешение администратора (\(created))."))
        }
        defer { AuthorizationFree(auth, [.destroyRights]) }

        var pipe: UnsafeMutablePointer<FILE>?
        let status = helper.withUnsafeFileSystemRepresentation { path in
            SSTPStartAuthorized(auth, path!, &pipe)
        }
        if status == errAuthorizationCanceled {
            onEvent(VPNEvent(type: "log", message: L("Запрос разрешения администратора отменён.")))
            return
        }
        guard status == errAuthorizationSuccess, let pipe else {
            throw Failure(L("macOS не запустила сетевой компонент (\(status))."))
        }

        let fd = fileno(pipe)
        _ = fcntl(fd, F_SETNOSIGPIPE, 1)
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        defer {
            lock.lock()
            descriptor = -1
            fclose(pipe)
            lock.unlock()
        }

        var data = try JSONEncoder().encode(request)
        data.append(10)
        try writeLine(data, to: fd)
        lock.lock()
        descriptor = fd
        if cancelled { _ = try? writeLine(Data("stop\n".utf8), to: fd) }
        lock.unlock()

        var pending = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        var finished = false
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            if count <= 0 { break }
            pending.append(contentsOf: buffer.prefix(count))
            while let end = pending.firstIndex(of: 10) {
                if let event = try? JSONDecoder().decode(VPNEvent.self, from: Data(pending[..<end])) {
                    if event.type == "finished" { finished = true }
                    else { onEvent(event) }
                }
                pending.removeSubrange(...end)
            }
            if finished { break }
            if pending.count > 65_536 { pending.removeAll() }
        }
        if !finished { throw Failure(L("Связь с сетевым компонентом прервалась.")) }
    }

    private func writeLine(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { bytes in
            guard let start = bytes.baseAddress else { return }
            var sent = 0
            while sent < bytes.count {
                let count = Darwin.write(fd, start.advanced(by: sent), bytes.count - sent)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw Failure(L("Не удалось передать данные сетевому компоненту.")) }
                sent += count
            }
        }
    }
}
