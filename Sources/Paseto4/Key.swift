import Foundation

public protocol Key {
    var material: Data { get }
    init(material: Data) throws
}

extension Key {
    var data: Data { self.material }
    
    init?(data: Data) {
        try? self.init(material: data)
    }
}

extension Key {
    public var encoded: String { self.material.base64URLEncodedString(noPadding: true) }

    public init(encoded: String) throws {
        guard let decoded = Data(base64URLEncoded: encoded) else {
            fatalError("TODO")
        }

        try self.init(material: decoded)
    }

    public init(hex: String) throws {
        let decoded = try Data(hexString: hex)
        try self.init(material: decoded)
    }
}
