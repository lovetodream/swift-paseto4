import XCTest
@testable import Paseto4

final class CodingTests: XCTestCase {
    func testClaims() throws {
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

        let encodedClaims = try Token.encoder.encode(claims)
        let decodedClaims = try Token.decoder.decode([String: String].self, from: encodedClaims)
        XCTAssertEqual(decodedClaims["aud"], claims.audience)
        XCTAssertEqual(decodedClaims["exp"], Token.timeFormatter.string(from: claims.expiration!))
        XCTAssertEqual(decodedClaims["iat"], Token.timeFormatter.string(from: claims.issuedAt!))
        XCTAssertEqual(decodedClaims["iss"], claims.issuer)
        XCTAssertEqual(decodedClaims["jti"], claims.jti)
        XCTAssertEqual(decodedClaims["nbf"], Token.timeFormatter.string(from: claims.notBefore!))
        XCTAssertEqual(decodedClaims["sub"], claims.subject)
        XCTAssertEqual(decodedClaims["id"].flatMap(Int.init), 0)
        
        let decodedClaimsAsClaims = try Token.decoder.decode(Token.Claims.self, from: encodedClaims)
        XCTAssertEqual(decodedClaimsAsClaims, claims)
    }
}
