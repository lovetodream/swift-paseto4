import Crypto
import struct Foundation.Data

public enum Public {
    public static func sign(_ package: Package, with key: AsymmetricSecretKey) throws -> Message<Public> {
        try self.sign(package, with: key, implicit: .init())
    }

    public static func verify(_ message: Message<Public>, with key: AsymmetricPublicKey) throws -> Package {
        try self.verify(message, with: key, implicit: .init())
    }

    public static func sign(_ package: Package, with key: AsymmetricSecretKey, implicit: Data) throws -> Message<Public> {
        let (data, footer) = (package.content, package.footer)

        let header = Header(version: .v4, purpose: .public)

        let signature = try Curve25519.Signing
            .PrivateKey(rawRepresentation: key.material)
            .signature(for: pae([header.data, data, footer, implicit]))

        let payload = Payload(message: data, signature: signature)

        return Message(payload: payload, footer: footer)
    }

    public static func verify(
        _ message: Message<Public>,
        with key: AsymmetricPublicKey,
        implicit: Data
    ) throws -> Package {
        let (header, footer) = (message.header, message.footer)

        let payload = message.payload

        guard try Curve25519.Signing
            .PublicKey(rawRepresentation: key.material)
            .isValidSignature(payload.signature, for: pae([header.data, payload.message, footer, implicit]))
        else {
            throw PasetoError.invalidSignature
        }

        return Package(payload.message, footer: footer)
    }
}

extension Public {
    public static func sign(
        _ data: Data, with key: AsymmetricSecretKey, footer: Data = Data()
    ) throws -> Message<Public> {
        try self.sign(Package(data, footer: footer), with: key)
    }
}
