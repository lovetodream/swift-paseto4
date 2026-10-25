import BLAKE2

public enum Local: Sendable {
    static func encrypt(
        content: Span<UInt8>,
        footer: Span<UInt8>,
        with key: SymmetricKey,
        implicit: Span<UInt8>,
        nonce givenNonce: Span<UInt8>?
    ) throws -> Message<Local> {
        let nonce: [32 of UInt8]

        if let given = givenNonce, given.count == Payload.nonceLength {
            nonce = .init(copying: given)
        } else {
            nonce = .random()
        }

        let keys = try key.split(nonce: nonce.span)

        let cipherText = XChaCha20.streamXOR(
            message: content,
            nonce: keys.nonce.span,
            key: keys.encryptionKey.span
        )

        let tag = try authenticationTag(
            nonce: nonce.span,
            cipherText: cipherText.span,
            footer: footer,
            implicit: implicit,
            key: keys.authenticationKey.span
        )

        let payload = Payload(nonce: nonce, cipherText: cipherText, mac: tag)

        return Message(payload: payload, footer: Array(copying: footer))
    }

    static func encrypt(
        _ package: Package,
        with key: SymmetricKey,
        implicit: Span<UInt8>,
        nonce: [UInt8]?
    ) throws -> Message<Local> {
        try self.encrypt(
            content: package.content.span,
            footer: package.footer.span,
            with: key,
            implicit: implicit,
            nonce: nonce?.span
        )
    }

    private static func authenticationTag(
        nonce: Span<UInt8>,
        cipherText: Span<UInt8>,
        footer: Span<UInt8>,
        implicit: Span<UInt8>,
        key: Span<UInt8>
    ) throws -> [32 of UInt8] {
        let header = Header(version: .v4, purpose: .local).bytes

        // Feed the pre-authentication encoding straight into the hasher instead of buffering it.
        var hasher = try BLAKE2b(key: key, digestLength: Payload.macLength)
        hasher.updatePAEHeader(pieceCount: 5)
        hasher.updatePAEPiece(header.span)
        hasher.updatePAEPiece(nonce)
        hasher.updatePAEPiece(cipherText)
        hasher.updatePAEPiece(footer)
        hasher.updatePAEPiece(implicit)

        let tag = hasher.finalize()
        return [32 of UInt8] { tag[$0] }
    }
}

extension Local {
    public static func encrypt(
        _ package: Package,
        with key: SymmetricKey
    ) throws -> Message<Local> {
        try self.encrypt(package, with: key, implicit: [UInt8]().span)
    }

    public static func decrypt(
        _ message: Message<Local>,
        with key: SymmetricKey
    ) throws -> Package {
        try self.decrypt(message, with: key, implicit: [UInt8]().span)
    }

    public static func encrypt(
        _ package: Package,
        with key: SymmetricKey,
        implicit: Span<UInt8>
    ) throws -> Message<Local> {
        try self.encrypt(package, with: key, implicit: implicit, nonce: nil)
    }

    public static func decrypt(
        _ message: Message<Local>,
        with key: SymmetricKey,
        implicit: Span<UInt8>
    ) throws -> Package {
        let payload = message.payload

        let keys = try key.split(nonce: payload.nonce.span)

        let expectedTag = try authenticationTag(
            nonce: payload.nonce.span,
            cipherText: payload.cipherText.span,
            footer: message.footer.span,
            implicit: implicit,
            key: keys.authenticationKey.span
        )

        guard constantTimeEqual(expectedTag.span, payload.mac.span) else {
            throw PasetoError.badMac
        }

        let plainText = XChaCha20.streamXOR(
            message: payload.cipherText.span,
            nonce: keys.nonce.span,
            key: keys.encryptionKey.span
        )
        return Package(plainText, footer: message.footer)
    }
}

extension Local {
    public static func encrypt(
        _ data: Span<UInt8>, with key: SymmetricKey
    ) throws -> Message<Local> {
        try self.encrypt(
            content: data, footer: [UInt8]().span, with: key, implicit: [UInt8]().span, nonce: nil
        )
    }

    public static func encrypt(
        _ data: Span<UInt8>, with key: SymmetricKey, footer: Span<UInt8>
    ) throws -> Message<Local> {
        try self.encrypt(
            content: data, footer: footer, with: key, implicit: [UInt8]().span, nonce: nil
        )
    }
}
