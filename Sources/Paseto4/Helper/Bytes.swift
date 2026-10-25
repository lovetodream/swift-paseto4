extension Array where Element == UInt8 {
    /// Creates an array by copying the bytes of a span.
    init(copying span: Span<UInt8>) {
        self = [UInt8](unsafeUninitializedCapacity: span.count) { buffer, initializedCount in
            span.withUnsafeBufferPointer { source in
                if let source = source.baseAddress, let destination = buffer.baseAddress {
                    destination.initialize(from: source, count: span.count)
                }
            }
            initializedCount = span.count
        }
    }

    /// Appends the bytes of a span.
    mutating func append(copying span: Span<UInt8>) {
        span.withUnsafeBufferPointer { self.append(contentsOf: $0) }
    }
}

extension InlineArray where Element == UInt8 {
    /// Creates an inline array by copying the bytes of a span.
    ///
    /// The span must contain at least as many bytes as the inline array.
    init(copying span: Span<UInt8>) {
        self.init { span[$0] }
    }

    /// Creates an inline array filled with cryptographically secure random bytes.
    static func random() -> Self {
        var result = Self(repeating: 0)
        var generator = SystemRandomNumberGenerator()

        // Draw 64 bits at a time instead of calling the generator once per byte.
        var span = result.mutableSpan
        span.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let word = generator.next()
                let count = Swift.min(8, bytes.count - offset)
                Swift.withUnsafeBytes(of: word) { source in
                    bytes.baseAddress!.advanced(by: offset)
                        .copyMemory(from: source.baseAddress!, byteCount: count)
                }
                offset += count
            }
        }

        return result
    }
}

/// Compares two byte sequences in constant time.
func constantTimeEqual(_ lhs: Span<UInt8>, _ rhs: Span<UInt8>) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for index in 0..<lhs.count {
        difference |= lhs[index] ^ rhs[index]
    }
    return difference == 0
}
