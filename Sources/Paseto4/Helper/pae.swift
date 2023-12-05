import Foundation

func pae<D: DataProtocol>(_ pieces: [D]) -> Data { 
    pieces.reduce(le64(pieces.count)) { partialResult, next in
        partialResult + le64(next.count) + next
    }
}

private func le64<T: FixedWidthInteger>(_ n: T) -> Data {
    // clear out the MSB
    let m = UInt64(n) & (UInt64.max >> 1)

    return Data((0..<8).map { UInt8(m >> (8 * $0) & 255) })
}
