extension Public: PayloadContainer {
    public struct Payload {
        static let signatureLength = 64

        let message: [UInt8]
        let signature: [64 of UInt8]
    }
}

extension Public.Payload: Payload {
    public var bytes: [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(self.message.count + Self.signatureLength)
        bytes.append(contentsOf: self.message)
        bytes.append(copying: self.signature.span)
        return bytes
    }

    public init?(bytes: [UInt8]) {
        let signatureOffset = bytes.count - Public.Payload.signatureLength

        guard signatureOffset > 0 else { return nil }

        self.init(
            message: Array(bytes[..<signatureOffset]),
            signature: [64 of UInt8] { bytes[signatureOffset + $0] }
        )
    }
}
