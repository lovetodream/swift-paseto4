import Foundation
import Testing
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


@Suite
struct VectorTest {
    @Test
    func version4() throws {
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
                        implicit: Array(test.implicitAssertion.utf8).span
                      )
                else {
                    #expect(test.expectFail, "\(test.name) was expected to fail")
                    continue
                }

                decoded = decrypted
            case .none:
                let pk = try AsymmetricPublicKey(hex: test.publicKey!)

                guard let message = Message<Public>(test.token),
                      let verified = try? Public.verify(
                        message,
                        with: pk,
                        implicit: Array(test.implicitAssertion.utf8).span
                      )
                else {
                    #expect(test.expectFail, "\(test.name) was expected to fail")
                    continue
                }

                decoded = verified
            }

            #expect(!test.expectFail, "\(test.name) was expected to fail but succeeded")

            guard let expected = test.payload else {
                #expect(Bool(false), "Unexpected empty test payload")
                continue
            }

            #expect(String(validating: decoded.content, as: UTF8.self) == expected, "\(test.name)")

            switch test.key {
            case .some:
                let sk = try SymmetricKey(hex: test.key!)

                let encrypted = try Local.encrypt(
                    Package(Array(expected.utf8), footer: Array(test.footer.utf8)),
                    with: sk,
                    implicit: Array(test.implicitAssertion.utf8).span,
                    nonce: [UInt8](hexString: test.nonce!)
                )

                #expect(encrypted.description == test.token, "\(test.name)")
            case .none:
                break
            }
        }
    }
}


