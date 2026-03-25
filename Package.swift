// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SebShark",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "SebShark", targets: ["SebShark"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-atomics.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: "SebSharkCore",
            dependencies: ["cBPFCapture"],
            path: "Sources/SebSharkCore",
            swiftSettings: [
                .unsafeFlags(["-strict-concurrency=complete"])
            ]
        ),
        .target(
            name: "cBPFCapture",
            path: "Sources/cBPFCapture",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "SebShark",
            dependencies: [
                "SebSharkCore",
                "cBPFCapture",
                .product(name: "Atomics", package: "swift-atomics"),
            ],
            path: "Sources/SebShark",
            swiftSettings: [
                .unsafeFlags(["-strict-concurrency=complete"])
            ]
        ),
        .testTarget(
            name: "SebSharkTests",
            dependencies: ["SebSharkCore"],
            path: "Tests/SebSharkTests"
        ),
    ]
)
