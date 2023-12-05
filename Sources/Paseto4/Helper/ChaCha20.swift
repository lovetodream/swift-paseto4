import struct Foundation.Data
import protocol Foundation.DataProtocol

// MARK: ChaCha20

private enum ChaCha20 {
    private struct Context {
        var input = [UInt32](repeating: 0, count: 16)
    }

    private static func keySetup(context: inout Context, key: [UInt8]) {
        context.input[0]  = 0x61707865
        context.input[1]  = 0x3320646e
        context.input[2]  = 0x79622d32
        context.input[3]  = 0x6b206574
        context.input[4]  = load32LE(key, at: 0)
        context.input[5]  = load32LE(key, at: 4)
        context.input[6]  = load32LE(key, at: 8)
        context.input[7]  = load32LE(key, at: 12)
        context.input[8]  = load32LE(key, at: 16)
        context.input[9]  = load32LE(key, at: 20)
        context.input[10] = load32LE(key, at: 24)
        context.input[11] = load32LE(key, at: 28)
    }

    private static func ivSetup(context: inout Context, iv: [UInt8], counter: [UInt8]?) {
        if counter == nil {
            context.input[12] = 0
            context.input[13] = 0
        } else {
            context.input[12] = load32LE(counter!, at: 0)
            context.input[13] = load32LE(counter!, at: 4)
        }
        context.input[14] = load32LE(iv, at: 0)
        context.input[15] = load32LE(iv, at: 4)
    }

    private static func encryptBytes(context: inout Context, message: [UInt8], out: inout [UInt8], bytes: Int) {
        var x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15: UInt32
        var j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15: UInt32
        var cursor = 0
        var messageCursor = 0
        var ctarget: [UInt8]? = nil
        var tmp = ArraySlice<UInt8>(repeating: 0, count: 64)
        var message = message
        var bytes = bytes

        j0  = context.input[0]
        j1  = context.input[1]
        j2  = context.input[2]
        j3  = context.input[3]
        j4  = context.input[4]
        j5  = context.input[5]
        j6  = context.input[6]
        j7  = context.input[7]
        j8  = context.input[8]
        j9  = context.input[9]
        j10 = context.input[10]
        j11 = context.input[11]
        j12 = context.input[12]
        j13 = context.input[13]
        j14 = context.input[14]
        j15 = context.input[15]

        while true {
            if bytes < 64 {
                tmp[0..<64] = ArraySlice(repeating: 0, count: 64)
                for i in 0..<bytes {
                    tmp[i] = message[i + messageCursor]
                }
                message[messageCursor...] = tmp
                ctarget = out
                out[cursor...] = tmp
            }
            x0  = j0
            x1  = j1
            x2  = j2
            x3  = j3
            x4  = j4
            x5  = j5
            x6  = j6
            x7  = j7
            x8  = j8
            x9  = j9
            x10 = j10
            x11 = j11
            x12 = j12
            x13 = j13
            x14 = j14
            x15 = j15
            for _ in 0..<10 {
                quarterRound(&x0, &x4, &x8, &x12)
                quarterRound(&x1, &x5, &x9, &x13)
                quarterRound(&x2, &x6, &x10, &x14)
                quarterRound(&x3, &x7, &x11, &x15)
                quarterRound(&x0, &x5, &x10, &x15)
                quarterRound(&x1, &x6, &x11, &x12)
                quarterRound(&x2, &x7, &x8, &x13)
                quarterRound(&x3, &x4, &x9, &x14)
            }
            x0  = x0 &+ j0
            x1  = x1 &+ j1
            x2  = x2 &+ j2
            x3  = x3 &+ j3
            x4  = x4 &+ j4
            x5  = x5 &+ j5
            x6  = x6 &+ j6
            x7  = x7 &+ j7
            x8  = x8 &+ j8
            x9  = x9 &+ j9
            x10 = x10 &+ j10
            x11 = x11 &+ j11
            x12 = x12 &+ j12
            x13 = x13 &+ j13
            x14 = x14 &+ j14
            x15 = x15 &+ j15

            x0  = x0 ^   load32LE(message, at: messageCursor + 0)
            x1  = x1 ^   load32LE(message, at: messageCursor + 4)
            x2  = x2 ^   load32LE(message, at: messageCursor + 8)
            x3  = x3 ^   load32LE(message, at: messageCursor + 12)
            x4  = x4 ^   load32LE(message, at: messageCursor + 16)
            x5  = x5 ^   load32LE(message, at: messageCursor + 20)
            x6  = x6 ^   load32LE(message, at: messageCursor + 24)
            x7  = x7 ^   load32LE(message, at: messageCursor + 28)
            x8  = x8 ^   load32LE(message, at: messageCursor + 32)
            x9  = x9 ^   load32LE(message, at: messageCursor + 36)
            x10 = x10 ^  load32LE(message, at: messageCursor + 40)
            x11 = x11 ^  load32LE(message, at: messageCursor + 44)
            x12 = x12 ^  load32LE(message, at: messageCursor + 48)
            x13 = x13 ^  load32LE(message, at: messageCursor + 52)
            x14 = x14 ^  load32LE(message, at: messageCursor + 56)
            x15 = x15 ^  load32LE(message, at: messageCursor + 60)

            j12 &+= 1

            if j12 == 0 {
                j13 += 1
            }

            out.withUnsafeMutableBufferPointer { c in
                store32LE(x0 , in: &c, at: cursor + 0 )
                store32LE(x1 , in: &c, at: cursor + 4 )
                store32LE(x2 , in: &c, at: cursor + 8 )
                store32LE(x3 , in: &c, at: cursor + 12)
                store32LE(x4 , in: &c, at: cursor + 16)
                store32LE(x5 , in: &c, at: cursor + 20)
                store32LE(x6 , in: &c, at: cursor + 24)
                store32LE(x7 , in: &c, at: cursor + 28)
                store32LE(x8 , in: &c, at: cursor + 32)
                store32LE(x9 , in: &c, at: cursor + 36)
                store32LE(x10, in: &c, at: cursor + 40)
                store32LE(x11, in: &c, at: cursor + 44)
                store32LE(x12, in: &c, at: cursor + 48)
                store32LE(x13, in: &c, at: cursor + 52)
                store32LE(x14, in: &c, at: cursor + 56)
                store32LE(x15, in: &c, at: cursor + 60)
            }

            if bytes <= 64 {
                if bytes < 64 {
                    for i in 0..<bytes {
                        ctarget![i] = out[i] // ctarget cannot be nil
                    }
                }
                context.input[12] = j12
                context.input[13] = j13

                return
            }
            bytes -= 64
            cursor += 64
            messageCursor += 64
        }
    }

    static func streamXORic(out: inout [UInt8], message: [UInt8], nonce: [UInt8], ic: UInt64 = 0, key: [UInt8]) {
        var context = Context()
        var icBytes = [UInt8](repeating: 0, count: 8)
        var icHigh: UInt32
        var icLow: UInt32

        icHigh = u32v(ic >> 32)
        icLow = u32v(ic)
        icBytes.withUnsafeMutableBufferPointer { ptr in
            store32LE(icLow, in: &ptr, at: 0)
            store32LE(icHigh, in: &ptr, at: 4)
        }
        self.keySetup(context: &context, key: key)
        self.ivSetup(context: &context, iv: nonce, counter: icBytes)
        self.encryptBytes(context: &context, message: message, out: &out, bytes: message.count)
    }
}

// MARK: XChaCha20

enum XChaCha20 {

    private static func streamXORic(out: inout [UInt8], message: [UInt8], nonce: [UInt8], key: [UInt8]) {
        var k2 = [UInt8](repeating: 0, count: 32)

        hchacha20Core(out: &k2, nonce: nonce, key: key)
        ChaCha20.streamXORic(out: &out, message: message, nonce: Array(nonce.suffix(from: 16)), key: k2)
    }

    private static func streamXOR<M: DataProtocol, N: DataProtocol, K: DataProtocol>(out: inout [UInt8], message: M, nonce: N, key: K) {
        self.streamXORic(out: &out, message: Array(message), nonce: Array(nonce), key: Array(key))
    }

    private static func hchacha20Core(out: inout [UInt8], nonce: [UInt8], key: [UInt8]) {
        var x0, x1, x2, x3, x4, x5, x6, x7: UInt32!
        var x8, x9, x10, x11, x12, x13, x14, x15: UInt32!

        x0 = 0x61707865
        x1 = 0x3320646e
        x2 = 0x79622d32
        x3 = 0x6b206574
        x4  = load32LE(key, at: 0)
        x5  = load32LE(key, at: 4)
        x6  = load32LE(key, at: 8)
        x7  = load32LE(key, at: 12)
        x8  = load32LE(key, at: 16)
        x9  = load32LE(key, at: 20)
        x10 = load32LE(key, at: 24)
        x11 = load32LE(key, at: 28)
        x12 = load32LE(nonce, at: 0)
        x13 = load32LE(nonce, at: 4)
        x14 = load32LE(nonce, at: 8)
        x15 = load32LE(nonce, at: 12)

        for _ in 0..<10 {
            quarterRound(&x0, &x4,  &x8, &x12)
            quarterRound(&x1, &x5,  &x9, &x13)
            quarterRound(&x2, &x6, &x10, &x14)
            quarterRound(&x3, &x7, &x11, &x15)
            quarterRound(&x0, &x5, &x10, &x15)
            quarterRound(&x1, &x6, &x11, &x12)
            quarterRound(&x2, &x7,  &x8, &x13)
            quarterRound(&x3, &x4,  &x9, &x14)
        }

        out.withUnsafeMutableBufferPointer { ptr in
            store32LE( x0, in: &ptr, at:  0)
            store32LE( x1, in: &ptr, at:  4)
            store32LE( x2, in: &ptr, at:  8)
            store32LE( x3, in: &ptr, at: 12)
            store32LE(x12, in: &ptr, at: 16)
            store32LE(x13, in: &ptr, at: 20)
            store32LE(x14, in: &ptr, at: 24)
            store32LE(x15, in: &ptr, at: 28)
        }
    }

    @inlinable
    static func streamXOR<M: DataProtocol, N: DataProtocol, K: DataProtocol>(message: M, nonce: N, key: K) -> Data {
        var cipherText = [UInt8](repeating: 0, count: message.count)
        self.streamXOR(out: &cipherText, message: message, nonce: nonce, key: key)
        return Data(cipherText.prefix(message.count))
    }
}

// MARK: - Util

@inline(__always)
private func u32v(_ v: UInt64) -> UInt32 {
    UInt32(truncatingIfNeeded: v) & 0xFFFFFFFF
}

@inline(__always)
private func quarterRound(_ a: inout UInt32, _ b: inout UInt32, _ c: inout UInt32, _ d: inout UInt32) {
    a &+= b; d = rotl32(d ^ a, 16)
    c &+= d; b = rotl32(b ^ c, 12)
    a &+= b; d = rotl32(d ^ a,  8)
    c &+= d; b = rotl32(b ^ c,  7)

}

@inline(__always)
private func rotl32(_ x: UInt32, _ b: UInt32) -> UInt32 {
    (x << b) | (x >> (32 - b))
}

@inline(__always)
private func load32LE(_ src: Array<UInt8>, at index: Int) -> UInt32 {
    var value = UInt32(src[index + 0])
    value |= UInt32(src[index + 1]) <<  8
    value |= UInt32(src[index + 2]) << 16
    value |= UInt32(src[index + 3]) << 24
    return value
}

private func store32LE(_ value: UInt32, in destination: inout UnsafeMutableBufferPointer<UInt8>, at index: Int) {
    destination[index + 0] = UInt8(truncatingIfNeeded: value)
    destination[index + 1] = UInt8(truncatingIfNeeded: value >> 8)
    destination[index + 2] = UInt8(truncatingIfNeeded: value >> 16)
    destination[index + 3] = UInt8(truncatingIfNeeded: value >> 24)
}
