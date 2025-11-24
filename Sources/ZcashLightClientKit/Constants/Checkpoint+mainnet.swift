//
//  WalletBirthday+mainnet.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 7/28/21.
//
import Foundation

extension Checkpoint {
    static let mainnetMin = Checkpoint(
        height: 227_520,
        hash: "0000000000003848c00178d5787cc9c8bbc30f87d65d511bbb0b7e567634d0a1",
        time: 1540954856,
        saplingTree: "000000",
        orchardTree: nil
    )

    static let mainnetCheckpointDirectory = Bundle.main.url(forResource: "zcash-mainnet", withExtension: "bundle")!
}
