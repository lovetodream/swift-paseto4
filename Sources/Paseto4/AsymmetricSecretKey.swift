import Crypto

public struct AsymmetricSecretKey: Sendable {
    static let length = 32 // + 32

    /// The 32 byte Ed25519 seed.
    public let material: [32 of UInt8]

    /// Kept around so signing doesn't have to derive the key every time.
    let privateKey: Curve25519.Signing.PrivateKey

    public init(material: [32 of UInt8]) {
        self.material = material
        self.privateKey = try! material.span.withUnsafeBytes {
            try Curve25519.Signing.PrivateKey(rawRepresentation: $0)
        }
    }
}

extension AsymmetricSecretKey: Key {
    public init(bytes: Span<UInt8>) {
        let length = AsymmetricSecretKey.length

        // a 64 byte secret key contains the public key as suffix
        guard bytes.count == length || bytes.count == 2 * length else {
            fatalError("TODO: bad length - secret key must be \(length) bytes long; \(bytes.count) given.")
        }

        self.init(material: .init(copying: bytes))
    }

    public var bytes: [UInt8] { Array(copying: self.material.span) }

    public var publicKey: AsymmetricPublicKey {
        let publicKey = self.privateKey.publicKey.rawRepresentation
        return AsymmetricPublicKey(material: [32 of UInt8] { publicKey[publicKey.startIndex + $0] })
    }

    public init() {
        let secretKey = Curve25519.Signing.PrivateKey().rawRepresentation
        self.init(material: [32 of UInt8] { secretKey[secretKey.startIndex + $0] })
    }
}
