// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecureAggregationClient",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "SecureAggregationClient",
            targets: [
                "SecureAggregationClient",
            ]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
//        .package(name: "SecureAggregationCore",
//                 url: "ssh://git@bitbucket.ase.in.tum.de:7999/mk/secureaggregationcore.git",
//                 Package.Dependency.Requirement.branch("master")),
        .package(name: "SecureAggregationCore", url: "../secureAggregationCore", Package.Dependency.Requirement.branch("master")),
        .package(name: "ShamirSecretShare", url: "git@github.com:StephanSchmiedmayer/SecretShare.swift.git", Package.Dependency.Requirement.branch("master")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SecureAggregationClient", 
            dependencies: [
                .product(name: "SecureAggregationCore", package: "SecureAggregationCore"),
                .product(name: "ShamirSecretShare", package: "ShamirSecretShare")
            ]),
        .testTarget(
            name: "SecureAggregationClientTests",
            dependencies: [
                "SecureAggregationClient",
            ]),
    ]
)
