import struct Foundation.Data

extension Public: PayloadContainer {
    public struct Payload {
        static let signatureLength = 64

        let message: Data
        let signature: Data
    }
}

extension Public.Payload: Payload {
    public var data: Data { self.message + self.signature }

    public init?(data: Data) {
        let signatureOffset = data.count - Public.Payload.signatureLength

        guard signatureOffset > 0 else { return nil }

        self.init(message: data[..<signatureOffset], signature: data[signatureOffset...])
    }

    public subscript(position: Int) -> UInt8 {
        self.data[position]
    }
}
