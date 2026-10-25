import Crypto

public enum Public: Sendable {
    static func sign(
        content: Span<UInt8>,
        footer: Span<UInt8>,
        with key: AsymmetricSecretKey,
        implicit: Span<UInt8>
    ) throws -> Message<Public> {
        let preAuth = Self.preAuthenticationEncoding(
            content: content, footer: footer, implicit: implicit
        )

        let signature = try key.privateKey.signature(for: preAuth)

        let payload = Payload(
            message: Array(copying: content),
            signature: [64 of UInt8] { signature[signature.startIndex + $0] }
        )

        return Message(payload: payload, footer: Array(copying: footer))
    }

    private static func preAuthenticationEncoding(
        content: Span<UInt8>,
        footer: Span<UInt8>,
        implicit: Span<UInt8>
    ) -> [UInt8] {
        let header = Header(version: .v4, purpose: .public).bytes

        var preAuth = PAE(
            pieceCount: 4,
            contentLength: header.count + content.count + footer.count + implicit.count
        )
        preAuth.append(header.span)
        preAuth.append(content)
        preAuth.append(footer)
        preAuth.append(implicit)
        return preAuth.bytes
    }
}

extension Public {
    public static func sign(_ package: Package, with key: AsymmetricSecretKey) throws -> Message<Public> {
        try self.sign(package, with: key, implicit: [UInt8]().span)
    }

    public static func verify(_ message: Message<Public>, with key: AsymmetricPublicKey) throws -> Package {
        try self.verify(message, with: key, implicit: [UInt8]().span)
    }

    public static func sign(
        _ package: Package, with key: AsymmetricSecretKey, implicit: Span<UInt8>
    ) throws -> Message<Public> {
        try self.sign(
            content: package.content.span,
            footer: package.footer.span,
            with: key,
            implicit: implicit
        )
    }

    public static func verify(
        _ message: Message<Public>,
        with key: AsymmetricPublicKey,
        implicit: Span<UInt8>
    ) throws -> Package {
        let payload = message.payload

        let preAuth = Self.preAuthenticationEncoding(
            content: payload.message.span,
            footer: message.footer.span,
            implicit: implicit
        )

        guard payload.signature.span.withUnsafeBytes({
            key.publicKey.isValidSignature($0, for: preAuth)
        }) else {
            throw PasetoError.invalidSignature
        }

        return Package(payload.message, footer: message.footer)
    }
}

extension Public {
    public static func sign(
        _ data: Span<UInt8>, with key: AsymmetricSecretKey
    ) throws -> Message<Public> {
        try self.sign(content: data, footer: [UInt8]().span, with: key, implicit: [UInt8]().span)
    }

    public static func sign(
        _ data: Span<UInt8>, with key: AsymmetricSecretKey, footer: Span<UInt8>
    ) throws -> Message<Public> {
        try self.sign(content: data, footer: footer, with: key, implicit: [UInt8]().span)
    }
}
