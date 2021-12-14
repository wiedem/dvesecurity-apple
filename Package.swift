// swift-tools-version:5.4

import PackageDescription

let package = Package(
    name: "DVESecurity",
    platforms: [
        .iOS(.v12),
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "DVESecurity",
            targets: ["DVESecurity", "DVESecurity_ObjC"]
        ),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "DVESecurity",
            dependencies: ["DVESecurity_ObjC"],
            path: "Source",
            exclude: [],
            publicHeadersPath: nil
        ),
        .target(
            name: "DVESecurity_ObjC",
            dependencies: [],
            path: "CSource/ObjC",
            exclude: ["ASN1/LICENSE", "ASN1/PKCS1.asn1", "ASN1/PKIX.asn1", "ASN1/Makefile.am.asn1convert", "ASN1/Makefile.am.libasncodec"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("ASN1"),
            ]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
