private let base64URLAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

private let base64URLDecodingIndex: [UInt8] = {
    var decoded = [UInt8](repeating: 0xFF, count: 256)
    for (value, digit) in base64URLAlphabet.enumerated() {
        decoded[Int(digit)] = UInt8(value)
    }
    return decoded
}()

func base64URLEncodedString(_ bytes: Span<UInt8>, noPadding: Bool = false) -> String {
    let fullGroups = bytes.count / 3
    let remainder = bytes.count % 3
    let paddedCount = (fullGroups + (remainder == 0 ? 0 : 1)) * 4
    let capacity = noPadding
        ? fullGroups * 4 + (remainder == 0 ? 0 : remainder + 1)
        : paddedCount

    return String(unsafeUninitializedCapacity: capacity) { output in
        var position = 0

        for group in 0..<fullGroups {
            let i = group * 3
            let chunk = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8 | UInt32(bytes[i + 2])
            output[position + 0] = base64URLAlphabet[Int(chunk >> 18 & 63)]
            output[position + 1] = base64URLAlphabet[Int(chunk >> 12 & 63)]
            output[position + 2] = base64URLAlphabet[Int(chunk >> 6 & 63)]
            output[position + 3] = base64URLAlphabet[Int(chunk & 63)]
            position += 4
        }

        if remainder > 0 {
            let i = fullGroups * 3
            let chunk = UInt32(bytes[i]) << 16 | (remainder == 2 ? UInt32(bytes[i + 1]) << 8 : 0)
            output[position + 0] = base64URLAlphabet[Int(chunk >> 18 & 63)]
            output[position + 1] = base64URLAlphabet[Int(chunk >> 12 & 63)]
            position += 2
            if remainder == 2 {
                output[position] = base64URLAlphabet[Int(chunk >> 6 & 63)]
                position += 1
            }
            if !noPadding {
                while position < paddedCount {
                    output[position] = UInt8(ascii: "=")
                    position += 1
                }
            }
        }

        return position
    }
}

/// Decodes unpadded, URL-safe base64. Returns `nil` for any invalid input.
func base64URLDecodedBytes<S: StringProtocol>(_ string: S) -> [UInt8]? {
    if let decoded = string.utf8.withContiguousStorageIfAvailable({ base64URLDecode($0) }) {
        return decoded
    }
    return Array(string.utf8).withUnsafeBufferPointer { base64URLDecode($0) }
}

private func base64URLDecode(_ input: UnsafeBufferPointer<UInt8>) -> [UInt8]? {
    var isValid = true

    let result = [UInt8](unsafeUninitializedCapacity: input.count * 3 / 4 + 1) { output, initializedCount in
        base64URLDecodingIndex.withUnsafeBufferPointer { table in
            var written = 0
            var accumulatedBits = 0
            var accumulator: UInt32 = 0

            for character in input {
                let value = table[Int(character)]
                if value == 0xFF {
                    isValid = false
                    break
                }

                accumulator = (accumulator << 6) | UInt32(value)
                accumulatedBits += 6
                if accumulatedBits >= 8 {
                    accumulatedBits -= 8
                    output[written] = UInt8(truncatingIfNeeded: accumulator >> UInt32(accumulatedBits))
                    written += 1
                }
            }

            // Leftover bits must be fewer than one symbol's worth and zero.
            if accumulatedBits > 4 || (accumulator & ((1 << UInt32(accumulatedBits)) - 1)) != 0 {
                isValid = false
            }

            initializedCount = written
        }
    }

    return isValid ? result : nil
}
