// swift-tools-version:5.7

import PackageDescription

let package = Package(
    name: "DVESecurity",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "DVESecurity",
            targets: ["DVESecurity"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMinor(from: "0.7.0"))
    ],
    targets: [
        .target(
            name: "DVESecurity",
            dependencies: [
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Source",
            exclude: []
        ),
    ],
    swiftLanguageVersions: [.v5]
)
