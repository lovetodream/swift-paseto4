import BLAKE2

/// Builds the Pre-Authentication Encoding of a fixed number of pieces into a single buffer.
struct PAE {
    private(set) var bytes: [UInt8]

    /// - Parameters:
    ///   - pieceCount: The number of pieces that will be appended.
    ///   - contentLength: The combined length of all pieces, used to size the buffer upfront.
    init(pieceCount: Int, contentLength: Int) {
        self.bytes = []
        self.bytes.reserveCapacity(8 + 8 * pieceCount + contentLength)
        self.bytes.append(copying: le64(pieceCount).span)
    }

    mutating func append(_ piece: Span<UInt8>) {
        self.bytes.append(copying: le64(piece.count).span)
        self.bytes.append(copying: piece)
    }
}

extension BLAKE2b {
    /// Starts the Pre-Authentication Encoding of `pieceCount` pieces, without buffering it.
    ///
    /// Follow up with ``updatePAEPiece(_:)`` once per piece.
    mutating func updatePAEHeader(pieceCount: Int) {
        self.update(data: le64(pieceCount).span)
    }

    /// Feeds one piece of the Pre-Authentication Encoding, without buffering it.
    mutating func updatePAEPiece(_ piece: Span<UInt8>) {
        self.update(data: le64(piece.count).span)
        self.update(data: piece)
    }
}

private func le64(_ n: Int) -> [8 of UInt8] {
    // clear out the MSB
    let m = UInt64(n) & (UInt64.max >> 1)
    return [8 of UInt8] { UInt8(truncatingIfNeeded: m >> (8 * UInt64($0))) }
}
