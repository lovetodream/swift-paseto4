import Benchmark
import Foundation
import Paseto4

let benchmarks: @Sendable () -> Void = {
    let configuration = Benchmark.Configuration(
        metrics: [.wallClock, .throughput, .mallocCountTotal],
        scalingFactor: .kilo
    )

    let message = [UInt8](repeating: 0x42, count: 1024)
    let symmetricKey = SymmetricKey()
    let secretKey = AsymmetricSecretKey()
    let publicKey = secretKey.publicKey

    let localMessage = try! Local.encrypt(message.span, with: symmetricKey)
    let publicMessage = try! Public.sign(message.span, with: secretKey)

    Benchmark("Local.encrypt", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try Local.encrypt(message.span, with: symmetricKey))
        }
    }

    Benchmark("Local.decrypt", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try Local.decrypt(localMessage, with: symmetricKey))
        }
    }

    Benchmark("Public.sign", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try Public.sign(message.span, with: secretKey))
        }
    }

    Benchmark("Public.verify", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try Public.verify(publicMessage, with: publicKey))
        }
    }

    Benchmark("Message.parse", configuration: configuration) { benchmark in
        let string = localMessage.description
        for _ in benchmark.scaledIterations {
            blackHole(Message<Local>(string))
        }
    }

    Benchmark("Message.description", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(localMessage.description)
        }
    }

    let token = Token(
        claims: Token.Claims(
            audience: "benchmark",
            expiration: Date(timeIntervalSince1970: 4_102_444_800),
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            issuer: "paseto",
            subject: "user-1234",
            additional: ["role": "admin"]
        ),
        footer: "{\"kid\":\"benchmark\"}"
    )
    let encryptedToken = try! token.encrypt(with: symmetricKey)
    let signedToken = try! token.sign(with: secretKey)

    Benchmark("Token.encrypt", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try token.encrypt(with: symmetricKey))
        }
    }

    Benchmark("Token.sign", configuration: configuration) { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try token.sign(with: secretKey))
        }
    }

    Benchmark("Parser<Local>.decrypt", configuration: configuration) { benchmark in
        let parser = Parser<Local>(rules: [])
        for _ in benchmark.scaledIterations {
            blackHole(try parser.decrypt(encryptedToken, with: symmetricKey))
        }
    }

    Benchmark("Parser<Public>.verify", configuration: configuration) { benchmark in
        let parser = Parser<Public>(rules: [])
        for _ in benchmark.scaledIterations {
            blackHole(try parser.verify(signedToken, with: publicKey))
        }
    }
}
