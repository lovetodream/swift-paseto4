extension Local: PayloadContainer {
    public struct Payload {
        static let nonceLength = 32
        static let macLength = 32

        let nonce: [32 of UInt8]
        let cipherText: [UInt8]
        let mac: [32 of UInt8]
    }
}

extension Local.Payload: Payload {
    public var bytes: [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(Self.nonceLength + self.cipherText.count + Self.macLength)
        bytes.append(copying: self.nonce.span)
        bytes.append(contentsOf: self.cipherText)
        bytes.append(copying: self.mac.span)
        return bytes
    }

    public init?(bytes: [UInt8]) {
        let nonceLength = Self.nonceLength
        let macLength = Self.macLength

        guard bytes.count > nonceLength + macLength else { return nil }

        let macOffset = bytes.count - macLength

        self.init(
            nonce: .init(copying: bytes.span),
            cipherText: Array(bytes[nonceLength..<macOffset]),
            mac: [32 of UInt8] { bytes[macOffset + $0] }
        )
    }
}
