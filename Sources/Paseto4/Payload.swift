import Foundation

public protocol Payload: DataProtocol {
    var data: Data { get }

    init?(data: Data)
}

extension Payload {
    public init?(encoded: String) {
        guard let data = Data(base64URLEncoded: encoded) else { return nil }
        self.init(data: data)
    }

    public var encoded: String { Data(self).base64URLEncodedString(noPadding: true) }
}

extension Payload {
    public var regions: Data.Regions {
        self.data.regions
    }

    public var startIndex: Data.Index {
        self.data.startIndex
    }

    public var endIndex: Data.Index {
        self.data.endIndex
    }
}
