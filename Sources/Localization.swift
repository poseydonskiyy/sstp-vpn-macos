import Foundation

enum AppLanguage: String, Codable {
    case en, ru
}

enum L10n {
    private static let resources = Bundle.main.resourceURL
    private(set) static var language = AppLanguage(
        rawValue: Bundle.main.preferredLocalizations.first ?? ""
    ) ?? .en
    private static var bundle = localizedBundle(language)

    // The GUI follows macOS per-app language preferences. The privileged helper
    // receives the GUI's choice before it starts producing connection events.
    static func use(_ language: AppLanguage) {
        self.language = language
        bundle = localizedBundle(language)
    }

    private static func localizedBundle(_ language: AppLanguage) -> Bundle? {
        guard let url = resources?.appendingPathComponent("\(language.rawValue).lproj") else { return nil }
        return Bundle(url: url)
    }

    static func string(_ message: LocalizedMessage) -> String {
        let template = bundle?.localizedString(forKey: message.key, value: message.key, table: nil) ?? message.key
        guard !message.arguments.isEmpty else { return template }
        // Scan the template once so braces in a profile name or an error stay literal.
        var result = ""
        var cursor = template.startIndex
        while let open = template[cursor...].firstIndex(of: "{"),
              let close = template[open...].firstIndex(of: "}") {
            result += template[cursor..<open]
            if let number = Int(template[template.index(after: open)..<close]),
               (1...message.arguments.count).contains(number) {
                result += message.arguments[number - 1]
            } else {
                result += template[open...close]
            }
            cursor = template.index(after: close)
        }
        return result + template[cursor...]
    }
}

struct LocalizedMessage: ExpressibleByStringInterpolation {
    let key: String
    let arguments: [String]

    init(stringLiteral value: String) {
        key = value
        arguments = []
    }

    init(stringInterpolation: StringInterpolation) {
        key = stringInterpolation.key
        arguments = stringInterpolation.arguments
    }

    struct StringInterpolation: StringInterpolationProtocol {
        var key = ""
        var arguments: [String] = []

        init(literalCapacity: Int, interpolationCount: Int) {
            key.reserveCapacity(literalCapacity)
            arguments.reserveCapacity(interpolationCount)
        }

        mutating func appendLiteral(_ text: String) {
            key += text
        }

        mutating func appendInterpolation(_ value: some Any) {
            arguments.append(String(describing: value))
            key += "{\(arguments.count)}"
        }
    }
}

func L(_ message: LocalizedMessage) -> String {
    L10n.string(message)
}
