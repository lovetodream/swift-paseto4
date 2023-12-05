import XCTest
@testable import Paseto4

struct TestVectors: Codable {
    let name: String
    let tests: [TestVector]

    struct TestVector: Codable {
        let name: String
        let nonce: String?
        let key: String?
        let publicKey: String?
        let secretKey: String?
        let token: String
        let payload: String?
        let footer: String

        let expectFail: Bool
        let implicitAssertion: String

        enum CodingKeys: String, CodingKey {
            case expectFail = "expect-fail"
            case implicitAssertion = "implicit-assertion"
            case publicKey = "public-key"
            case secretKey = "secret-key"

            case name
            case nonce
            case key
            case token
            case payload
            case footer
        }
    }
}


class VectorTest: XCTestCase {
    func testVersion4() throws {
        let contentsURL = Bundle.module.url(forResource: "TestVectors/v4", withExtension: "json")!
        let contents = try Data(contentsOf: contentsURL)


        let tests = try! JSONDecoder().decode(TestVectors.self, from: contents).tests

        for test in tests {
            let decoded: Package

            switch test.key {
            case .some:
                let sk = try SymmetricKey(hex: test.key!)

                guard let message = Message<Local>(test.token),
                      let decrypted = try? Local.decrypt(
                        message,
                        with: sk,
                        implicit: test.implicitAssertion.data(using: .utf8)!
                      )
                else {
                    XCTAssertTrue(test.expectFail, test.name)
                    continue
                }

                decoded = decrypted
            case .none:
                let pk = try AsymmetricPublicKey(hex: test.publicKey!)

                guard let message = Message<Public>(test.token),
                      let verified = try? Public.verify(
                        message,
                        with: pk,
                        implicit: test.implicitAssertion.data(using: .utf8)!
                      )
                else {
                    XCTAssertTrue(test.expectFail, test.name)
                    continue
                }

                decoded = verified
            }

            XCTAssertFalse(test.expectFail, test.name)

            guard let expected = test.payload else {
                XCTFail("Unexpected empty test payload")
                continue
            }

            XCTAssertEqual(String(data: decoded.content, encoding: .utf8), expected, test.name)

            switch test.key {
            case .some:
                let sk = try SymmetricKey(hex: test.key!)

                let encrypted = try Local.encrypt(
                    Package(expected.data(using: .utf8)!, footer: test.footer.data(using: .utf8)!),
                    with: sk,
                    implicit: test.implicitAssertion.data(using: .utf8)!,
                    nonce: Data(hexString: test.nonce!)
                )

                XCTAssertEqual(encrypted.description, test.token, test.name)
            case .none:
                break
            }
        }
    }
}


