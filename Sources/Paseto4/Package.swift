import struct Foundation.Data

public struct Package {
    public let content: Data
    public let footer: Data

    public init(_ content: Data, footer: Data = Data()) {
        self.content = content
        self.footer = footer
    }
}
