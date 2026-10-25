enum Version: String {
    case v4 = "v4"
}

struct Header: Equatable, Sendable {
    let version: Version
    let purpose: Purpose

    init(version: Version, purpose: Purpose) {
        self.version = version
        self.purpose = purpose
    }

    init?<V: StringProtocol, P: StringProtocol>(version: V, purpose: P) {
        guard let version = Version(rawValue: String(version)),
              let purpose = Purpose(rawValue: String(purpose))
        else { return nil }

        self.init(version: version, purpose: purpose)
    }

    init?(serialized: String) {
        let parts = serialized.split(separator: ".")

        guard parts.count == 3, parts[2] == "" else { return nil }

        self.init(version: parts[0], purpose: parts[1])
    }
}

extension Header: CustomStringConvertible {
    var description: String {
        return [self.version.rawValue, self.purpose.rawValue].joined(separator: ".") + "."
    }
}

extension Header {
    private static let localBytes = Array("v4.local.".utf8)
    private static let publicBytes = Array("v4.public.".utf8)

    /// The serialized header, e.g. `v4.local.`.
    var bytes: [UInt8] {
        switch self.purpose {
        case .local: Self.localBytes
        case .public: Self.publicBytes
        }
    }
}
