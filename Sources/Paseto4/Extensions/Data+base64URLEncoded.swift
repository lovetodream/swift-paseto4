import Foundation

private let base64URLDecodingIndex: [UInt8] = {
    var decoded = [UInt8](repeating: 0xFF, count: 256)
    for (value, digit) in [UInt8]("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8).enumerated() {
        decoded[Int(digit)] = UInt8(value)
    }
    return decoded
}()

extension Data {
    func base64URLEncodedString(noPadding: Bool = false) -> String {
        let encoded = self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        if noPadding {
            return encoded
                .replacingOccurrences(of: "=", with: "")
        }
        return encoded
    }

    init?(base64URLEncoded base64String: String) {
        guard let b64 = base64String.data(using: .utf8) else { return nil }
        let b64Length = b64.count
        var b64Position = 0
        var binaryPosition = 0
        let binaryCapacity = b64Length * 3 / 4 + 1
        var data = Data(repeating: 0, count: binaryCapacity)

        var accLength = 0
        var acc: Int32 = 0
        var d: Int32
        var c: UInt8

        while b64Position < b64Length {
            c = b64[b64Position]
            d = Int32(base64URLDecodingIndex[Int(c)])
            if d == 0xFF {
                break
            }
            acc = (acc << 6) + d
            accLength += 6
            if accLength >= 8 {
                accLength -= 8
                if binaryPosition >= .max { // Int.max threshold, e.g. max data length
                    return nil
                }
                data[binaryPosition] = UInt8((acc >> accLength) & 0xFF)
                binaryPosition += 1
            }
            b64Position += 1
        }

        if accLength > 4 || (acc & ((1 << accLength) - 1)) != 0 {
            return nil
        }

        if b64Position != b64Length {
            return nil
        }

        self = data.prefix(binaryPosition)
    }
}
