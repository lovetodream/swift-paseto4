enum ByteHexEncodingErrors: Error {
    case incorrectHexValue
    case incorrectString
}

private func htoi(_ value: UInt8) throws -> UInt8 {
    switch value {
    case UInt8(ascii: "0")...UInt8(ascii: "9"):
        return value - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"):
        return value - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"):
        return value - UInt8(ascii: "A") + 10
    default:
        throw ByteHexEncodingErrors.incorrectHexValue
    }
}

extension Array where Element == UInt8 {
    init(hexString: String) throws {
        let characters = Array(hexString.utf8)

        if characters.count % 2 != 0 || characters.isEmpty {
            throw ByteHexEncodingErrors.incorrectString
        }

        self.init()
        self.reserveCapacity(characters.count / 2)

        for i in stride(from: 0, to: characters.count, by: 2) {
            self.append(try htoi(characters[i]) << 4 | htoi(characters[i + 1]))
        }
    }
}
