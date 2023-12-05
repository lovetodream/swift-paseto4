import Crypto
import struct Foundation.Data

public struct AsymmetricPublicKey {
    static let length = 32

    public let material: Data

    public init(material: Data) {
        guard material.count == AsymmetricPublicKey.length else {
            fatalError("TODO: bad length - Public key must be 32 bytes long; \(material.count) given.")
        }

        self.material = material
    }
}

extension AsymmetricPublicKey: Key { }
