// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Login",
    platforms: [
        .iOS(.v16), .macOS(.v12)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "Login",
            targets: ["Login"]),
    ],
    dependencies: [
        .package(url: "https://github.com/pointfreeco/swift-dependencies.git", .upToNextMajor(from: "1.3.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "Login",
            dependencies: [
                .product(name: "Dependencies", package: "swift-dependencies")
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "LoginTests",
            dependencies: ["Login"]),
    ]
)
