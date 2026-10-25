public struct Package {
    public let content: [UInt8]
    public let footer: [UInt8]

    public init(_ content: [UInt8], footer: [UInt8] = []) {
        self.content = content
        self.footer = footer
    }
}
