import struct Foundation.Data

extension Local: PayloadContainer {
    public struct Payload {
        static let nonceLength = 32
        static let macLength = 32

        let nonce: Data
        let cipherText: Data
        let mac: Data
    }
}

extension Local.Payload: Payload {
    public var data: Data { self.nonce + self.cipherText + self.mac }

    public init?(data: Data) {
        let nonceLength = Self.nonceLength
        let macLength = Self.macLength

        guard data.count > nonceLength + macLength else { return nil }

        let macOffset = data.count - macLength

        self.init(
            nonce: data[..<nonceLength], 
            cipherText: data[nonceLength..<macOffset],
            mac: data[macOffset...]
        )
    }
    
    public subscript(position: Int) -> UInt8 {
        self.data[position]
    }

}
