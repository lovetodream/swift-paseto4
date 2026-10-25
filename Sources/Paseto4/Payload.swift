public protocol Payload: Sendable {
    /// A copy of the payload's serialized bytes.
    var bytes: [UInt8] { get }

    init?(bytes: [UInt8])
}

extension Payload {
    public init?<S: StringProtocol>(encoded: S) {
        guard let bytes = base64URLDecodedBytes(encoded) else { return nil }
        self.init(bytes: bytes)
    }

    public var encoded: String { base64URLEncodedString(self.bytes.span, noPadding: true) }
}
