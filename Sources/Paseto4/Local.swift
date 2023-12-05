import BLAKE2
import struct Foundation.Data

public enum Local {
    static func encrypt(_ package: Package, with key: SymmetricKey, implicit: Data, nonce givenNonce: Data?) throws -> Message<Local> {
        let (message, footer) = (package.content, package.footer)
        let nonceLength = Payload.nonceLength

        let nonce: Data

        if let given = givenNonce, given.count == nonceLength {
            nonce = given
        } else {
            nonce = .random(length: nonceLength)
        }

        let (encKey, authKey, nonce2) = try key.split(nonce: nonce)

        let cipherText = XChaCha20.streamXOR(message: message, nonce: nonce2, key: encKey)

        let header = Header(version: .v4, purpose: .local)
        let preAuth = pae([header.data, nonce, cipherText, footer, implicit])

        let tag = try BLAKE2b.hash(data: preAuth, key: authKey, digestLength: Payload.macLength)

        let payload = Payload(nonce: nonce, cipherText: cipherText, mac: tag)

        return Message(payload: payload, footer: footer)
    }

    static func encrypt(_ data: Data, with key: SymmetricKey, footer: Data, implicit: Data, nonce: Data?) throws -> Message<Local> {
        try self.encrypt(Package(data, footer: footer), with: key, implicit: implicit, nonce: nonce)
    }
}

extension Local {
    public static func encrypt(
        _ package: Package,
        with key: SymmetricKey
    ) throws -> Message<Local> {
        try self.encrypt(package, with: key, implicit: .init())
    }

    public static func decrypt(
        _ message: Message<Local>,
        with key: SymmetricKey
    ) throws -> Package {
        try self.decrypt(message, with: key, implicit: .init())
    }

    public static func encrypt(
        _ package: Package,
        with key: SymmetricKey,
        implicit: Data
    ) throws -> Message<Local> {
        try self.encrypt(package, with: key, implicit: implicit, nonce: nil)
    }

    public static func decrypt(
        _ message: Message<Local>,
        with key: SymmetricKey,
        implicit: Data
    ) throws -> Package {
        let (header, footer) = (message.header, message.footer)

        let nonce = message.payload.nonce
        let cipherText = message.payload.cipherText
        let givenTag = message.payload.mac

        let (encKey, authKey, nonce2) = try key.split(nonce: nonce)

        let preAuth = pae([header.data, nonce, cipherText, footer, implicit])

        let expectedTag = try BLAKE2b.hash(
            data: preAuth,
            key: authKey,
            digestLength: Payload.macLength
        )

        guard expectedTag == givenTag else {
            throw PasetoError.badMac
        }


        let plainText = XChaCha20.streamXOR(message: cipherText, nonce: nonce2, key: encKey)
        return Package(plainText, footer: footer)
    }
}

extension Local {
    public static func encrypt(
        _ data: Data, with key: SymmetricKey, footer: Data = Data()
    ) throws -> Message<Local> {
        try self.encrypt(Package(data, footer: footer), with: key)
    }
}
