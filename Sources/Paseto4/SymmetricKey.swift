import BLAKE2

private let encryptionKeyDomain = Array("paseto-encryption-key".utf8)
private let authenticationKeyDomain = Array("paseto-auth-key-for-aead".utf8)

public struct SymmetricKey: Key {
    static let length = 32

    public let material: [32 of UInt8]

    public init(material: [32 of UInt8]) {
        self.material = material
    }

    public init(bytes: Span<UInt8>) {
        guard bytes.count == Self.length else {
            fatalError("TODO: bad length - Symmetric key must be \(Self.length) bytes long; \(bytes.count) given.")
        }

        self.init(material: .init(copying: bytes))
    }

    public init() {
        self.init(material: .random())
    }

    public var bytes: [UInt8] { Array(copying: self.material.span) }
}

extension SymmetricKey {
    func split(
        nonce: Span<UInt8>
    ) throws -> (encryptionKey: [32 of UInt8], authenticationKey: [32 of UInt8], nonce: [24 of UInt8]) {
        guard nonce.count == Local.Payload.nonceLength else {
            fatalError(
                "TODO: Nonce must be exactly "
                + String(Local.Payload.nonceLength)
                + " bytes"
            )
        }

        var encryptionHasher = try BLAKE2b(key: self.material.span, digestLength: 56)
        encryptionHasher.update(data: encryptionKeyDomain.span)
        encryptionHasher.update(data: nonce)
        let tmp = encryptionHasher.finalize()

        var authenticationHasher = try BLAKE2b(key: self.material.span, digestLength: 32)
        authenticationHasher.update(data: authenticationKeyDomain.span)
        authenticationHasher.update(data: nonce)
        let authenticationKey = authenticationHasher.finalize()

        return (
            [32 of UInt8] { tmp[$0] },
            [32 of UInt8] { authenticationKey[$0] },
            [24 of UInt8] { tmp[32 + $0] }
        )
    }
}
