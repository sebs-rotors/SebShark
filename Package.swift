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
        .executableTarget(
            name: "SebShark",
            dependencies: [
                .product(name: "Atomics", package: "swift-atomics"),
            ],
            path: "Sources/SebShark",
            swiftSettings: [
                .unsafeFlags(["-strict-concurrency=complete"])
            ]
        ),
    ]
)
