import Foundation

public struct Token: Sendable {
    public var claims: Claims
    public var footer: String

    public struct Claims: Decodable, Sendable {
        public var audience: String?
        public var expiration: Date?
        public var issuedAt: Date?
        public var issuer: String?
        public var jti: String?
        public var notBefore: Date?
        public var subject: String?
        /// Additional custom claims.
        public var additional: [String: (LosslessStringConvertible & Sendable)?] = [:]

        enum CodingKeys: String, CodingKey, CaseIterable {
            case audience = "aud"
            case expiration = "exp"
            case issuedAt = "iat"
            case issuer = "iss"
            case jti = "jti"
            case notBefore = "nbf"
            case subject = "sub"
            case additional // unused
        }

        /// Used for testing and encoding.
        internal var asDictionary: [String: String] {
            var dict: [String: String] = additional.reduce(into: [:], { partialResult, pair in
                if pair.value != nil {
                    partialResult[pair.key] = String(pair.value!)
                }
            })
            if let audience {
                dict["aud"] = audience
            }
            if let expiration {
                dict["exp"] = Token.timeFormatter.string(from: expiration)
            }
            if let issuedAt {
                dict["iat"] = Token.timeFormatter.string(from: issuedAt)
            }
            if let issuer {
                dict["iss"] = issuer
            }
            if let jti {
                dict["jti"] = jti
            }
            if let notBefore {
                dict["nbf"] = Token.timeFormatter.string(from: notBefore)
            }
            if let subject {
                dict["sub"] = subject
            }
            return dict
        }

        public init(
            audience: String? = nil,
            expiration: Date? = nil,
            issuedAt: Date? = nil,
            issuer: String? = nil,
            jti: String? = nil,
            notBefore: Date? = nil,
            subject: String? = nil,
            additional: [String: (LosslessStringConvertible & Sendable)?] = [:]
        ) {
            self.audience = audience
            self.expiration = expiration
            self.issuedAt = issuedAt
            self.issuer = issuer
            self.jti = jti
            self.notBefore = notBefore
            self.subject = subject
            self.additional = additional
        }

        public init(from decoder: Decoder) throws {
            let container: KeyedDecodingContainer<Token.Claims.CodingKeys> = try decoder.container(keyedBy: Token.Claims.CodingKeys.self)
            self.audience = try container.decodeIfPresent(String.self, forKey: Token.Claims.CodingKeys.audience)
            self.expiration = try container.decodeIfPresent(Date.self, forKey: Token.Claims.CodingKeys.expiration)
            self.issuedAt = try container.decodeIfPresent(Date.self, forKey: Token.Claims.CodingKeys.issuedAt)
            self.issuer = try container.decodeIfPresent(String.self, forKey: Token.Claims.CodingKeys.issuer)
            self.jti = try container.decodeIfPresent(String.self, forKey: Token.Claims.CodingKeys.jti)
            self.notBefore = try container.decodeIfPresent(Date.self, forKey: Token.Claims.CodingKeys.notBefore)
            self.subject = try container.decodeIfPresent(String.self, forKey: Token.Claims.CodingKeys.subject)
            let additionalContainer = try decoder.singleValueContainer()
            self.additional = try additionalContainer.decode([String: String?].self)
            for key in Token.Claims.CodingKeys.allCases where key != .additional {
                self.additional.removeValue(forKey: key.rawValue)
            }
        }

        public func encode(using encoder: JSONEncoder) throws -> Data {
            try encoder.encode(self.asDictionary)
        }
    }

    static let timeFormatter = ISO8601DateFormatter()
    static let decoder: JSONDecoder = {
        var decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
    static let encoder: JSONEncoder = {
        var encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    public init(claims: Claims, footer: String = "") {
        self.claims = claims
        self.footer = footer
    }

    public init(encodedData: Data, footer: String) throws {
        self.claims = try Self.decoder.decode(Claims.self, from: encodedData)
        self.footer = footer
    }
}

public extension Token {
    func sign(with key: AsymmetricSecretKey) throws -> String {
        try Public.sign(
            self.claims.encode(using: Token.encoder),
            with: key,
            footer: Data(footer.utf8)
        ).description
    }

    func encrypt(with key: SymmetricKey) throws -> String {
        try Local.encrypt(
            self.claims.encode(using: Token.encoder),
            with: key,
            footer: Data(footer.utf8)
        ).description
    }
}

extension Token.Claims: Equatable {
    public static func == (lhs: Token.Claims, rhs: Token.Claims) -> Bool {
        lhs.asDictionary == rhs.asDictionary
    }
}
