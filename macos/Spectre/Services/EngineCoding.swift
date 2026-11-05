import Foundation

/// RFC 3339 parsing that tolerates any number of fractional-second digits
/// (the engine emits microseconds; `ISO8601DateFormatter` accepts at most
/// milliseconds reliably).
enum EngineDate {
    // ISO8601DateFormatter is documented as thread-safe.
    nonisolated(unsafe) private static let internetDateTime: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    nonisolated(unsafe) private static let fullDate: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter
    }()

    static func parse(_ raw: String) -> Date? {
        guard let dot = raw.firstIndex(of: ".") else { return internetDateTime.date(from: raw) }
        let afterDot = raw[raw.index(after: dot)...]
        let digits = afterDot.prefix { $0.isNumber }
        let fraction = Double("0." + digits) ?? 0
        let base = String(raw[..<dot]) + String(afterDot.dropFirst(digits.count))
        return internetDateTime.date(from: base)?.addingTimeInterval(fraction)
    }

    /// `YYYY-MM-DD` (breach dates) or a full timestamp.
    static func day(from raw: String) -> Date? {
        fullDate.date(from: raw) ?? parse(raw)
    }

    /// A timestamp or `YYYY-MM-DD` from the engine as a readable date, or the
    /// raw text when it does not parse.
    static func display(_ raw: String) -> String {
        guard let date = day(from: raw) else { return raw }
        let includesTime = raw.count > 10
        return includesTime ? date.formatted(date: .abbreviated, time: .shortened) : date.formatted(date: .abbreviated, time: .omitted)
    }

    static func format(_ date: Date) -> String {
        internetDateTime.string(from: date)
    }
}

enum EngineCoding {
    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            guard let date = EngineDate.parse(raw) else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "invalid RFC 3339 date \(raw)")
            }
            return date
        }
        return decoder
    }

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(EngineDate.format(date))
        }
        return encoder
    }
}
