import Crypto

public struct AsymmetricPublicKey: Sendable {
    static let length = 32

    public let material: [32 of UInt8]

    /// Kept around so verifying doesn't have to parse the key every time.
    let publicKey: Curve25519.Signing.PublicKey

    public init(material: [32 of UInt8]) {
        self.material = material
        self.publicKey = try! material.span.withUnsafeBytes {
            try Curve25519.Signing.PublicKey(rawRepresentation: $0)
        }
    }
}

extension AsymmetricPublicKey: Key {
    public init(bytes: Span<UInt8>) {
        guard bytes.count == AsymmetricPublicKey.length else {
            fatalError("TODO: bad length - Public key must be 32 bytes long; \(bytes.count) given.")
        }

        self.init(material: .init(copying: bytes))
    }

    public var bytes: [UInt8] { Array(copying: self.material.span) }
}
