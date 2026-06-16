//
//  WalletBirthday+testnet.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 7/28/21.
//

import Foundation

extension Checkpoint {
    static let testnetMin = Checkpoint(
        height: 1,
        hash: "000004c52f3047ccc50d71a6b2a9a035fafd2605cc5b49c2c1d07a202a7d3b33",
        time: 1712527210,
        tree: "000000",
        //orchardTree: nil
    )
    
    static let testnetCheckpointDirectory = Bundle.module.bundleURL.appendingPathComponent("checkpoints/vrsctest/")
}
