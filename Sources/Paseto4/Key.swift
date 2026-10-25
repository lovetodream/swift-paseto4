public protocol Key: Sendable {
    /// A copy of the raw key material.
    var bytes: [UInt8] { get }
    init(bytes: Span<UInt8>) throws
}

extension Key {
    public var encoded: String { base64URLEncodedString(self.bytes.span, noPadding: true) }

    public init(encoded: String) throws {
        guard let decoded = base64URLDecodedBytes(encoded) else {
            fatalError("TODO")
        }

        try self.init(bytes: decoded.span)
    }

    public init(hex: String) throws {
        let decoded = try [UInt8](hexString: hex)
        try self.init(bytes: decoded.span)
    }
}
