import Foundation
import Security

struct CertificateInfo: Identifiable {
    let id: Data
    let subject: String
    let starts: Date
    let expires: Date

    var current: Bool { starts <= Date() && expires > Date() }
    var expiring: Bool { expires.timeIntervalSinceNow <= 30 * 86_400 }
}

enum Certificates {
    static func parse(_ input: Data) throws -> [CertificateInfo] {
        guard !input.isEmpty, input.count <= 256 * 1024 else {
            throw Failure("Выберите сертификат или цепочку размером до 256 КБ.")
        }
        var blocks: [Data] = []
        if let text = String(data: input, encoding: .utf8), text.contains("-----BEGIN") {
            let expression = try NSRegularExpression(
                pattern: "-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\s]+?)\\s*-----END CERTIFICATE-----"
            )
            let range = NSRange(text.startIndex..., in: text)
            let remaining = expression.stringByReplacingMatches(in: text, range: range, withTemplate: "")
            guard remaining.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw Failure("В PEM-файле должны быть только блоки CERTIFICATE.")
            }
            for match in expression.matches(in: text, range: range) {
                guard let range = Range(match.range(at: 1), in: text),
                      let der = Data(base64Encoded: text[range].filter { !$0.isWhitespace }) else {
                    throw Failure("Один из сертификатов PEM повреждён.")
                }
                blocks.append(der)
            }
        } else {
            blocks = [input]
        }
        guard !blocks.isEmpty, blocks.count <= 256 else {
            throw Failure("Импортируйте от 1 до 256 сертификатов.")
        }
        var seen: Set<Data> = []
        return try blocks.filter { seen.insert($0).inserted }.map { der in
            guard let certificate = SecCertificateCreateWithData(nil, der as CFData),
                  let values = SecCertificateCopyValues(certificate, [
                      kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter,
                  ] as CFArray, nil) as? [String: [String: Any]],
                  let starts = date(values[kSecOIDX509V1ValidityNotBefore as String]),
                  let expires = date(values[kSecOIDX509V1ValidityNotAfter as String]) else {
                throw Failure("Не удалось прочитать сертификат X.509 или срок его действия.")
            }
            let subject = SecCertificateCopySubjectSummary(certificate).map { $0 as String } ?? "Сертификат X.509"
            return CertificateInfo(id: der, subject: subject, starts: starts, expires: expires)
        }
    }

    private static func date(_ properties: [String: Any]?) -> Date? {
        let value = properties?[kSecPropertyKeyValue as String]
        if let date = value as? Date { return date }
        if let number = value as? NSNumber { return Date(timeIntervalSinceReferenceDate: number.doubleValue) }
        return nil
    }

    static func pem(_ certificates: [CertificateInfo]) -> Data {
        let text = certificates.map {
            "-----BEGIN CERTIFICATE-----\n" +
                $0.id.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
                "\n-----END CERTIFICATE-----\n"
        }.joined()
        return Data(text.utf8)
    }
}
