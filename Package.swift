// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "swift-paseto",
    products: [
        .library(name: "Paseto", targets: ["Paseto"]),
    ],
    targets: [
        .target(name: "Paseto"),
        .testTarget(name: "PasetoTests", dependencies: ["Paseto"]),
    ]
)
