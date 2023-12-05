import struct Foundation.Data

public protocol PayloadContainer {
    associatedtype Payload: Paseto4.Payload
}

public struct Message<Container: PayloadContainer> {
    typealias Payload = Container.Payload

    let header: Header = Message.header
    let payload: Payload
    let footer: Data

    init(payload: Payload, footer: Data = Data()) {
        self.payload = payload
        self.footer = footer
    }

    public init?(_ string: String) {
        guard let (
            header, encodedPayload, encodedFooter
        ) = Message.deconstruct(string) else { return nil }

        guard header == Message.header,
              let payload = Payload(encoded: String(encodedPayload)),
              let footer = Data(base64URLEncoded: String(encodedFooter))
        else { return nil }

        self.init(payload: payload, footer: footer)
    }

    static func deconstruct(
        _ string: String
    ) -> (header: Header, encodedPayload: Substring, encodedFooter: Substring)? {
        let parts = string.split(separator: ".")

        guard [3, 4].contains(parts.count) else { return nil }

        guard let header = Header(version: parts[0], purpose: parts[1])
        else { return nil }

        return (header, parts[2], parts.count > 3 ? parts[3] : "")
    }

    static var header: Header {
        Header(
            version: Version.v4,
            purpose: Purpose(payload: Payload.self)
        )
    }
}

extension Message: CustomStringConvertible {
    public var description: String {
        let main = self.header.description + payload.encoded
        guard !self.footer.isEmpty else { return main }
        return "\(main).\(self.footer.base64URLEncodedString(noPadding: true))"
    }
}

extension Message {
    func token(package: Package) throws -> Token {
        guard let footer = String(data: package.footer, encoding: .utf8) else {
            fatalError(
                "TODO: Could not convert the footer to a UTF-8 string."
            )
        }

        return try Token(
            encodedData: package.content,
            footer: footer
        )
    }
}

extension Message where Container == Public {
    public func verify(with key: AsymmetricPublicKey) throws -> Token {
        let package = try Container.verify(self, with: key)
        return try self.token(package: package)
    }
}

extension Message where Container == Local {
    public func decrypt(with key: SymmetricKey) throws -> Token {
        let package = try Container.decrypt(self, with: key)
        return try self.token(package: package)
    }
}
