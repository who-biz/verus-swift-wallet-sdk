//
//  BundleCheckpointURLProvider.swift
//  
//
//  Created by Francisco Gindre on 2023-10-30.
//

import Foundation

struct BundleCheckpointURLProvider {
    var url: (NetworkType) -> URL
}

extension BundleCheckpointURLProvider {
    /// Attempts to resolve the platform. `#if os(macOS)` implies that the build is for a macOS
    /// target, otherwise we assume the build is for an iOS target.
    static let `default` = BundleCheckpointURLProvider { networkType in
        #if os(macOS)
        Self.macOS.url(networkType)
        #else
        Self.iOS.url(networkType)
        #endif
    }

    static let iOS = BundleCheckpointURLProvider(url: { networkType in
        switch networkType {
        case .mainnet:
            return Checkpoint.mainnetCheckpointDirectory
        case .testnet:
            return Checkpoint.testnetCheckpointDirectory
        }
    })

    /// This variant attempts to retrieve the saplingActivation checkpoint for the given network
    /// type using `Bundle.module.url(forResource:withExtension:subdirectory:localization)`.
    /// If not found it will return `WalletBirthday.mainnetCheckpointDirectory` or
    /// `WalletBirthday.testnetCheckpointDirectory`. This responds to tests failing on a macOS
    /// target because the checkpoint resources would not be found.
    static let macOS = BundleCheckpointURLProvider(url: { networkType in
        switch networkType {
        case .mainnet:
            return Bundle.module.url(
                forResource: "227520",
                withExtension: "json",
                subdirectory: "checkpoints/vrsc/",
                localization: nil
            )?
            .deletingLastPathComponent() ?? Checkpoint.mainnetCheckpointDirectory
        case .testnet:
            return Bundle.module.url(
                forResource: "1",
                withExtension: "json",
                subdirectory: "checkpoints/vrsctest/",
                localization: nil
            )?
            .deletingLastPathComponent() ?? Checkpoint.testnetCheckpointDirectory
        }
    })
}
