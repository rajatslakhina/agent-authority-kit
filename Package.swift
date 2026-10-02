// swift-tools-version: 6.0
import PackageDescription

// Platforms are exactly the ones CI builds: macOS (`swift test`) and the iOS
// Simulator (`xcodebuild build`). Linux is covered by the Linux CI job; on Linux
// `CryptoKit` does not exist, so the core module uses apple/swift-crypto there
// (API-compatible with CryptoKit) and nothing else changes.
let package = Package(
    name: "AgentAuthority",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "AgentAuthority", targets: ["AgentAuthority"]),
        .library(name: "AgentAuthorityUI", targets: ["AgentAuthorityUI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(
            name: "AgentAuthority",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ]
        ),
        .target(
            name: "AgentAuthorityUI",
            dependencies: ["AgentAuthority"]
        ),
        .testTarget(
            name: "AgentAuthorityTests",
            dependencies: ["AgentAuthority"]
        ),
        .testTarget(
            name: "AgentAuthorityUITests",
            dependencies: ["AgentAuthorityUI", "AgentAuthority"]
        ),
    ]
)
