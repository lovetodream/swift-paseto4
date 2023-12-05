import Crypto
import struct Foundation.Data

public struct AsymmetricSecretKey {
    static let length = 32 // + 32
    static let seedLength = 32
    static let keyPairLength = 96

    public let material: Data

    public init(material: Data) throws {
        let length = AsymmetricSecretKey.length

        if material.count == 64 { // contains public key as suffix
            self.material = material.prefix(32)
            return
        }

        guard material.count == length else {
            fatalError("TODO: bad length - secret key must be \(length) bytes long; \(material.count) given.")
        }

        self.material = material
    }
}

extension AsymmetricSecretKey {
    init(keyPair material: Data) throws {
        let keyPairLength = AsymmetricSecretKey.keyPairLength

        guard material.count == keyPairLength else {
            fatalError("TODO: bad length - Key pair must be \(keyPairLength) bytes long; \(material.count) given.")
        }

        self.material = material
    }

    init(seed material: Data) throws {
        let seedLength = AsymmetricSecretKey.seedLength

        guard material.count == seedLength else {
            fatalError("TODO: bad length - Seed must be \(seedLength) bytes long; \(material.count) given.")
        }

        self.material = try Curve25519.Signing.PrivateKey(rawRepresentation: material).rawRepresentation
    }
}

extension AsymmetricSecretKey: Key {
    var seed: Data {
        self.material[..<AsymmetricSecretKey.seedLength]
    }

    public var publicKey: AsymmetricPublicKey {
        AsymmetricPublicKey(data: try! Curve25519.Signing.PrivateKey(rawRepresentation: self.seed).publicKey.rawRepresentation)!
    }

    public init() {
        let secretKey = Curve25519.Signing.PrivateKey().rawRepresentation
        try! self.init(material: secretKey)
    }
}
