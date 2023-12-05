import XCTest
@testable import Paseto4

final class PasetoTests: XCTestCase {
    func testSign() throws {
        let sk = AsymmetricSecretKey()

        let message = "Hello world!".data(using: .utf8)!

        let signedBlob = try Public.sign(message, with: sk)

        let verified = try Public.verify(signedBlob, with: sk.publicKey)

        XCTAssertEqual(message, verified.content)
    }

    func testEncrypt() throws {
        let sk = SymmetricKey()

        let message = """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec
            pretium orci enim, tincidunt bibendum diam suscipit et.
            Pellentesque vel sagittis sem, vitae tempor elit. Sed non suscipit
            augue. In hac habitasse platea dictumst. Nunc consectetur et urna
            ac molestie. Nunc eleifend nisi nisl, non ornare nunc auctor sit
            amet. Sed eu sodales nibh. Etiam eros mi, molestie in nibh in,
            cursus ullamcorper augue. Duis id vestibulum nulla. Nulla in
            fermentum arcu. Nunc et nibh nec lacus pellentesque vulputate
            commodo vel sapien. Sed molestie, dui ac condimentum feugiat, magna
            risus tincidunt est, feugiat faucibus est magna at arcu. 👻
            """.data(using: .utf8)!

        let encryptedBlob = try Local.encrypt(message, with: sk)

        let decrypted = try Local.decrypt(encryptedBlob, with: sk)

        XCTAssertEqual(message, decrypted.content)
    }

    func testLargeData() throws {
        let sk = SymmetricKey()

        let message = Data.random(length: 1 << 25)

        let blob = try Local.encrypt(message, with: sk)

        let result = try Local.decrypt(blob, with: sk).content

        XCTAssertEqual(message, result)
    }

    func testReadmeExample() {
        let rawToken = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"

        let key = try! AsymmetricPublicKey(
            hex: "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        )

        let parser = Parser<Public>(rules: [])
        let token = try! parser.verify(rawToken, with: key)

        XCTAssertEqual(
            ["data": "this is a signed message", "exp": "2022-01-01T00:00:00Z"],
            token.claims.asDictionary
        )

        XCTAssertEqual("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}", token.footer)
    }

    func testDocExample() throws {
        let key = SymmetricKey()
        let message = try Local.encrypt("Hello world!".data(using: .utf8)!, with: key)
        let pasetoString = message.description
        let verySensitiveKeyMaterial = key.encoded

        let importedKey = try! SymmetricKey(encoded: verySensitiveKeyMaterial)
        let importedMessage = Message<Local>(pasetoString)!
        let decrypted = try! Local.decrypt(importedMessage, with: importedKey)

        XCTAssertEqual("Hello world!", String(data: decrypted.content, encoding: .utf8))
    }
}

extension Data {
    static func random(length: Int) -> Data {
        var data = Data(repeating: 0, count: length)
        data.withUnsafeMutableBytes {
            assert($0.count == length)
            $0.initializeWithRandomBytes(count: length)
        }
        return data
    }
}


// MARK: - Initially from swift-crypto

extension UnsafeMutableRawBufferPointer {
    @inlinable
    func initializeWithRandomBytes(count: Int) {
        guard count > 0 else {
            return
        }

        precondition(count <= self.count)
        var rng = SystemRandomNumberGenerator()

        // We store bytes 64-bits at a time until we can't anymore.
        var targetPtr = self
        while targetPtr.count > 8 {
            targetPtr.storeBytes(of: rng.next(), as: UInt64.self)
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[8...])
        }

        // Now we're down to having to store things an integer at a time. We do this by shifting and
        // masking.
        var remainingWord: UInt64 = rng.next()
        while targetPtr.count > 0 {
            targetPtr.storeBytes(of: UInt8(remainingWord & 0xFF), as: UInt8.self)
            remainingWord >>= 8
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[1...])
        }
    }
}
