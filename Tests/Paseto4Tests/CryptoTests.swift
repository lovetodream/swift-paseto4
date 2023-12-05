import XCTest
@testable import Paseto4

final class CryptoTests: XCTestCase {
    func testSimplePayload() {
        let res = XChaCha20.streamXOR(
            message: [212, 181, 70, 116, 208, 31, 118, 190, 224, 254, 186],
            nonce: [UInt8](repeating: 0, count: 24),
            key: [UInt8](repeating: 0, count: 32)
        )
        XCTAssertEqual(String(data: res, encoding: .utf8), "hello world")
    }

    func testWithNonceAndKey() {
        let cipherText: [UInt8] = [
            16, 2, 190, 188, 61, 46, 0, 93, 238, 200, 127, 246, 96, 122, 199, 
            100, 80, 203, 210, 194, 199, 5, 148, 9, 117, 166, 78, 71, 11, 71,
            188, 144, 10, 94, 106, 163, 31, 26, 143, 251, 58, 144, 103, 192,
            147, 128, 109, 143, 85, 237, 101, 58, 105, 187, 187, 224, 201,
            156, 80, 79, 24, 88, 8, 154, 2, 181, 72, 241, 114,
        ]
        let key: [UInt8] = [
            195, 43, 142, 28, 82, 37, 80, 200, 133, 77, 81, 119, 235, 44, 169, 
            106, 204, 32, 114, 227, 202, 88, 64, 126, 14, 226, 246, 71, 14,
            146, 228, 159,
        ]
        let nonce: [UInt8] = [
            18, 154, 35, 209, 112, 237, 220, 228, 152, 103, 212, 136, 141, 39,
            99, 144, 171, 247, 228, 142, 85, 15, 235, 124,
        ]
        let expected: [UInt8] = [
            123, 34, 100, 97, 116, 97, 34, 58, 34, 116, 104, 105, 115, 32, 105, 
            115, 32, 97, 32, 115, 101, 99, 114, 101, 116, 32, 109, 101, 115,
            115, 97, 103, 101, 34, 44, 34, 101, 120, 112, 34, 58, 34, 50, 48,
            50, 50, 45, 48, 49, 45, 48, 49, 84, 48, 48, 58, 48, 48, 58, 48, 48,
            43, 48, 48, 58, 48, 48, 34, 125,
        ]
        // check nonce and key stuff!
        let res = XChaCha20.streamXOR(message: cipherText, nonce: nonce, key: key)
        XCTAssertEqual(expected, Array(res))
    }

    func testURLSafeNoPaddingBase64Invalid() {
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQh"
        let data = Data(base64URLEncoded: b64)
        XCTAssertNil(data)
    }

    func testURLSafeNoPaddingBase64Valid() {
        let b64s: [(String, Data?)] = [
            ("32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA", nil),
            ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg", Data([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 2, 190, 188, 61, 46, 0, 93,
                238, 200, 127, 246, 96, 122, 199, 100, 80, 203, 210, 194, 199,
                5, 148, 9, 117, 166, 78, 71, 11, 71, 188, 144, 10, 94, 106, 163,
                31, 26, 143, 251, 58, 144, 103, 192, 147, 128, 109, 143, 85, 
                237, 101, 58, 105, 187, 187, 224, 201, 156, 80, 79, 24, 88, 8,
                154, 2, 181, 72, 241, 114, 121, 132, 230, 255, 226, 255, 81,
                152, 57, 39, 120, 221, 18, 247, 103, 113, 208, 229, 184, 166,
                12, 187, 162, 108, 96, 127, 116, 188, 115, 114, 229, 66
            ]))
        ]

        for b64 in b64s.suffix(1) {
            let data = Data(base64URLEncoded: b64.0)
            XCTAssertNotNil(data)
            if let expected = b64.1 {
                XCTAssertEqual(data, expected)
            }
        }
    }
}
