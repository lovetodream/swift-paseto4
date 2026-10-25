// MARK: XChaCha20

enum XChaCha20 {
    private typealias State = InlineArray<16, UInt32>

    /// Encrypts or decrypts `message` with XChaCha20 (counter starts at `0`).
    ///
    /// - Parameters:
    ///   - message: The data to transform.
    ///   - nonce: Exactly `24` bytes.
    ///   - key: Exactly `32` bytes.
    static func streamXOR(message: Span<UInt8>, nonce: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        precondition(nonce.count == 24, "XChaCha20 nonce must be 24 bytes")
        precondition(key.count == 32, "XChaCha20 key must be 32 bytes")

        let subkey = hchacha20(nonce: nonce, key: key)

        var input = State(repeating: 0)
        input[0] = 0x61707865
        input[1] = 0x3320646e
        input[2] = 0x79622d32
        input[3] = 0x6b206574
        for i in 0..<8 { input[4 + i] = subkey[i] }
        // input[12] and input[13] are the block counter, which starts at zero.
        input[14] = load32LE(nonce, at: 16)
        input[15] = load32LE(nonce, at: 20)

        return [UInt8](unsafeUninitializedCapacity: message.count) { output, initializedCount in
            var offset = 0
            while offset < message.count {
                var x = input
                rounds(&x)
                for i in 0..<16 { x[i] &+= input[i] }

                let blockLength = min(64, message.count - offset)
                if blockLength == 64 {
                    for i in 0..<16 {
                        store32LE(x[i] ^ load32LE(message, at: offset + 4 * i), in: output, at: offset + 4 * i)
                    }
                } else {
                    for i in 0..<blockLength {
                        let keyStreamByte = UInt8(truncatingIfNeeded: x[i / 4] >> UInt32(8 * (i % 4)))
                        output[offset + i] = message[offset + i] ^ keyStreamByte
                    }
                }

                input[12] &+= 1
                if input[12] == 0 {
                    input[13] &+= 1
                }
                offset += 64
            }
            initializedCount = message.count
        }
    }

    /// Derives the 256 bit subkey as eight little-endian words.
    private static func hchacha20(nonce: Span<UInt8>, key: Span<UInt8>) -> InlineArray<8, UInt32> {
        var x = State(repeating: 0)
        x[0] = 0x61707865
        x[1] = 0x3320646e
        x[2] = 0x79622d32
        x[3] = 0x6b206574
        for i in 0..<8 { x[4 + i] = load32LE(key, at: 4 * i) }
        for i in 0..<4 { x[12 + i] = load32LE(nonce, at: 4 * i) }

        rounds(&x)

        return InlineArray<8, UInt32> { i in i < 4 ? x[i] : x[12 + i - 4] }
    }

    private static func rounds(_ x: inout State) {
        for _ in 0..<10 {
            quarterRound(&x, 0, 4,  8, 12)
            quarterRound(&x, 1, 5,  9, 13)
            quarterRound(&x, 2, 6, 10, 14)
            quarterRound(&x, 3, 7, 11, 15)
            quarterRound(&x, 0, 5, 10, 15)
            quarterRound(&x, 1, 6, 11, 12)
            quarterRound(&x, 2, 7,  8, 13)
            quarterRound(&x, 3, 4,  9, 14)
        }
    }
}

// MARK: - Util

@inline(__always)
private func quarterRound(_ x: inout InlineArray<16, UInt32>, _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
    x[a] &+= x[b]; x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] &+= x[d]; x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] &+= x[b]; x[d] = rotl32(x[d] ^ x[a],  8)
    x[c] &+= x[d]; x[b] = rotl32(x[b] ^ x[c],  7)
}

@inline(__always)
private func rotl32(_ x: UInt32, _ b: UInt32) -> UInt32 {
    (x << b) | (x >> (32 - b))
}

@inline(__always)
private func load32LE(_ src: Span<UInt8>, at index: Int) -> UInt32 {
    var value = UInt32(src[index + 0])
    value |= UInt32(src[index + 1]) <<  8
    value |= UInt32(src[index + 2]) << 16
    value |= UInt32(src[index + 3]) << 24
    return value
}

@inline(__always)
private func store32LE(_ value: UInt32, in destination: UnsafeMutableBufferPointer<UInt8>, at index: Int) {
    destination[index + 0] = UInt8(truncatingIfNeeded: value)
    destination[index + 1] = UInt8(truncatingIfNeeded: value >> 8)
    destination[index + 2] = UInt8(truncatingIfNeeded: value >> 16)
    destination[index + 3] = UInt8(truncatingIfNeeded: value >> 24)
}
