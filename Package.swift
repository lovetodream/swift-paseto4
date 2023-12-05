// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "swift-paseto4",
    platforms: [.macOS(.v11), .iOS(.v14), .watchOS(.v7), .tvOS(.v14)],
    products: [
        .library(name: "Paseto4", targets: ["Paseto4"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/lovetodream/swift-blake2", from: "0.1.0"),
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
