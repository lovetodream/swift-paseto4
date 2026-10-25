// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "swift-paseto4",
    platforms: [.macOS(.v26), .macCatalyst(.v26), .iOS(.v26), .watchOS(.v26), .tvOS(.v26), .visionOS(.v26)],
    products: [
        .library(name: "Paseto4", targets: ["Paseto4"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0"),
        .package(url: "https://github.com/lovetodream/swift-blake2", from: "0.2.0"),
    ],
    targets: [
        .target(name: "Paseto4", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
            .product(name: "BLAKE2", package: "swift-blake2"),
        ]),
        .testTarget(
            name: "Paseto4Tests", dependencies: ["Paseto4"], resources: [.copy("TestVectors")]
        ),
    ]
)


if Context.environment["PASETO_BENCHMARK"] != nil {
    package.dependencies.append(
        .package(url: "https://github.com/ordo-one/benchmark", from: "1.27.0")
    )
    package.targets.append(
        .executableTarget(
            name: "Paseto4Benchmarks",
            dependencies: [
                "Paseto4",
                .product(name: "Benchmark", package: "benchmark"),
            ],
            path: "Benchmarks/Paseto4Benchmarks",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "benchmark")
            ]
        )
    )
}
