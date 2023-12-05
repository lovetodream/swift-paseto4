import Foundation

public enum RuleResult {
    case pass
    case violation(Error)
}

public typealias Rule = (Token) -> RuleResult

public enum Rules { }

enum RuleError: LocalizedError {
    case missingClaim(String)
    case invalidClaim(String, actual: String, expected: String)
    case tokenExpired
    case tokenNotYetIssued
    case tokenNotYetActive

    var errorDescription: String? {
        switch self {
        case .missingClaim(let name):
            "The claim '\(name)' was not present."
        case .invalidClaim(let name, let actual, let expected):
            "Expected '\(name)' to be '\(expected)', but received '\(actual)'."
        case .tokenExpired:
            "This token has expired."
        case .tokenNotYetIssued:
            "The given time predates the token's issued at time."
        case .tokenNotYetActive:
            "The given time predates the token's not before time."
        }
    }
}

public extension Rules {
    static func forAudience(_ audience: String) -> Rule {
        return { token in
            guard let aud = token.audience else {
                return .violation(RuleError.missingClaim("aud"))
            }

            guard aud == audience else {
                return .violation(RuleError.invalidClaim("aud", actual: aud, expected: audience))
            }

            return .pass
        }
    }

    static func identifiedBy(_ identifier: String) -> Rule {
        return { token in
            guard let jti = token.jti else {
                return .violation(RuleError.missingClaim("jti"))
            }

            guard jti == identifier else {
                return .violation(RuleError.invalidClaim("jti", actual: jti, expected: identifier))
            }

            return .pass
        }
    }

    static func issuedBy(_ issuer: String) -> Rule {
        return { token in
            guard let iss = token.issuer else {
                return .violation(RuleError.missingClaim("iss"))
            }

            guard iss == issuer else {
                return .violation(RuleError.invalidClaim("iss", actual: iss, expected: issuer))
            }

            return .pass
        }
    }

    static func notExpired() -> Rule {
        return { token in
            guard let exp = token.expiration else {
                return .violation(RuleError.missingClaim("exp"))
            }

            guard Date() < exp else {
                return .violation(RuleError.tokenExpired)
            }

            return .pass
        }
    }

    static func subject(_ subject: String) -> Rule {
        return { token in
            guard let sub = token.subject else {
                return .violation(RuleError.missingClaim("iss"))
            }

            guard sub == subject else {
                return .violation(RuleError.invalidClaim("sub", actual: sub, expected: subject))
            }

            return .pass
        }
    }

    static func validAt(_ time: Date) -> Rule {
        return { token in
            guard let iat = token.issuedAt else {
                return .violation(RuleError.missingClaim("iat"))
            }
            guard time >= iat else {
                return .violation(RuleError.tokenNotYetIssued)
            }

            guard let nbf = token.notBefore else {
                return .violation(RuleError.missingClaim("nbf"))
            }
            guard time >= nbf else {
                return .violation(RuleError.tokenNotYetActive)
            }

            guard let exp = token.expiration else {
                return .violation(RuleError.missingClaim("exp"))
            }
            guard time < exp else {
                return .violation(RuleError.tokenExpired)
            }

            return .pass
        }
    }
}

public extension Token {
    var audience: String? {
        get { self.claims.audience }
        set { self.claims.audience = newValue }
    }

    var expiration: Date? {
        get { self.claims.expiration }
        set { self.claims.expiration = newValue }
    }

    var issuedAt: Date? {
        get { self.claims.issuedAt }
        set { self.claims.issuedAt = newValue }
    }

    var issuer: String? {
        get { self.claims.issuer }
        set { self.claims.issuer = newValue }
    }

    var jti: String? {
        get { self.claims.jti }
        set { self.claims.jti = newValue }
    }

    var notBefore: Date? {
        get { self.claims.notBefore }
        set { self.claims.notBefore = newValue }
    }

    var subject: String? {
        get { self.claims.subject }
        set { self.claims.subject = newValue }
    }
}
