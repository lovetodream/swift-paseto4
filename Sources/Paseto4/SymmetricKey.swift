import Crypto
import BLAKE2
import struct Foundation.Data

public struct SymmetricKey: Key {
    static let length = 32

    public let material: Data

    public init(material: Data) {
        self.material = material
    }

    public init() {
        self.init(data: .random(length: Self.length))!
    }
}

extension SymmetricKey {
    func split(nonce: Data) throws -> (ek: Data, ak: Data, n2: Data) {
        guard nonce.count == Local.Payload.nonceLength else {
            fatalError(
                "TODO: Nonce must be exactly "
                + String(Local.Payload.nonceLength)
                + " bytes"
            )
        }

        let tmp = try BLAKE2b.hash(
            data: "paseto-encryption-key".data(using: .utf8)! + nonce,
            key: self.material, digestLength: 56
        )

        let encKey = tmp[0..<32]
        let nonce2 = tmp[32..<56]

        let authKey = try BLAKE2b.hash(
            data: "paseto-auth-key-for-aead".data(using: .utf8)! + nonce,
            key: self.material, digestLength: 32
        )

        return (encKey, authKey, nonce2)
    }
}
