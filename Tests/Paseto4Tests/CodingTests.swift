import Foundation
import Testing
@testable import Paseto4

@Suite
struct CodingTests {
    @Test
    func claims() throws {
        let claims = Token.Claims(
            audience: "com.test.paseto",
            expiration: Date().addingTimeInterval(1_000_000),
            issuedAt: Date(), 
            issuer: "com.test.paseto.server",
            jti: UUID().uuidString,
            notBefore: Date(),
            subject: "test",
            additional: ["id": 0]
        )

        let encodedClaims = try claims.encode(using: Token.encoder)
        let decodedClaims = try Token.decoder.decode([String: String].self, from: encodedClaims)
        #expect(decodedClaims["aud"] == claims.audience)
        #expect(decodedClaims["exp"] == claims.expiration!.formatted(.iso8601))
        #expect(decodedClaims["iat"] == claims.issuedAt!.formatted(.iso8601))
        #expect(decodedClaims["iss"] == claims.issuer)
        #expect(decodedClaims["jti"] == claims.jti)
        #expect(decodedClaims["nbf"] == claims.notBefore!.formatted(.iso8601))
        #expect(decodedClaims["sub"] == claims.subject)
        #expect(decodedClaims["id"].flatMap(Int.init) == 0)

        let decodedClaimsAsClaims = try Token.decoder.decode(Token.Claims.self, from: encodedClaims)
        #expect(decodedClaimsAsClaims == claims)
    }
}
