//
//  ZcashKeyDerivationBackend.swift
//  
//
//  Created by Francisco Gindre on 4/7/23.
//

import Foundation

struct ZcashKeyDerivationBackend: ZcashKeyDerivationBackendWelding {
    let networkType: NetworkType

    // MARK: Address metadata and validation
    static func getAddressMetadata(_ address: String) -> AddressMetadata? {
        var networkId: UInt32 = 0
        var addrId: UInt32 = 0
        guard zcashlc_get_address_metadata(
            [CChar](address.utf8CString),
            &networkId,
            &addrId
        ) else {
            return nil
        }

        guard
            let network = NetworkType.forNetworkId(networkId),
            let addrType = AddressType.forId(addrId)
        else {
            return nil
        }

        return AddressMetadata(network: network, addrType: addrType)
    }

    func receiverTypecodesOnUnifiedAddress(_ address: String) throws -> [UInt32] {
        guard !address.containsCStringNullBytesBeforeStringEnding() else {
            throw ZcashError.rustReceiverTypecodesOnUnifiedAddressContainsNullBytes(address)
        }

        var len = UInt(0)

        guard let typecodesPointer = zcashlc_get_typecodes_for_unified_address_receivers(
            [CChar](address.utf8CString),
            &len
        ), len > 0
        else {
            throw ZcashError.rustRustReceiverTypecodesOnUnifiedAddressMalformed
        }

        var typecodes: [UInt32] = []

        for typecodeIndex in 0 ..< Int(len) {
            let pointer = typecodesPointer.advanced(by: typecodeIndex)

            typecodes.append(pointer.pointee)
        }

        defer {
            zcashlc_free_typecodes(typecodesPointer, len)
        }

        return typecodes
    }

    func isValidSaplingAddress(_ address: String) -> Bool {
        guard !address.containsCStringNullBytesBeforeStringEnding() else {
            return false
        }

        return zcashlc_is_valid_sapling_address([CChar](address.utf8CString), networkType.networkId)
    }

    func isValidSaplingExtendedFullViewingKey(_ key: String) -> Bool {
        guard !key.containsCStringNullBytesBeforeStringEnding() else {
            return false
        }

        return zcashlc_is_valid_viewing_key([CChar](key.utf8CString), networkType.networkId)
    }

    func isValidSaplingExtendedSpendingKey(_ key: String) -> Bool {
        guard !key.containsCStringNullBytesBeforeStringEnding() else {
            return false
        }

        return zcashlc_is_valid_sapling_extended_spending_key([CChar](key.utf8CString), networkType.networkId)
    }

    func isValidTransparentAddress(_ address: String) -> Bool {
        guard !address.containsCStringNullBytesBeforeStringEnding() else {
            return false
        }

        return zcashlc_is_valid_transparent_address([CChar](address.utf8CString), networkType.networkId)
    }

    func isValidUnifiedAddress(_ address: String) -> Bool {
        guard !address.containsCStringNullBytesBeforeStringEnding() else {
            return false
        }

        return zcashlc_is_valid_unified_address([CChar](address.utf8CString), networkType.networkId)
    }

    func isValidUnifiedFullViewingKey(_ key: String) -> Bool {
        guard !key.containsCStringNullBytesBeforeStringEnding() else {
            return false
        }

        return zcashlc_is_valid_unified_full_viewing_key([CChar](key.utf8CString), networkType.networkId)
    }

    // MARK: Address Derivation

    func deriveUnifiedSpendingKey(
        transparent_key: [UInt8]?,
        extsk: [UInt8]?,
        seed: [UInt8]?,
        accountIndex: Int32
    ) throws -> UnifiedSpendingKey {

        guard !(transparent_key?.isEmpty ?? true)
                || !(extsk?.isEmpty ?? true)
                || !(seed?.isEmpty ?? true) else {
            throw ZcashError.rustDeriveUnifiedSpendingKey(
                "All input arrays (`transparent_key`, `extsk`, `seed`) are empty — cannot derive unified spending key."
            )
        }

        let binaryKeyPtr = transparent_key!.withUnsafeBufferPointer { transparentBufferPtr in
            extsk!.withUnsafeBufferPointer { extskBufferPtr in
                seed!.withUnsafeBufferPointer { seedBufferPtr in
                    zcashlc_derive_spending_key(
                        transparentBufferPtr.baseAddress, UInt(transparent_key!.count),
                        extskBufferPtr.baseAddress, UInt(extsk!.count),
                        seedBufferPtr.baseAddress, UInt(seed!.count),
                        accountIndex,
                        networkType.networkId
                    )
                }
            }
        }

        defer { zcashlc_free_binary_key(binaryKeyPtr) }

        guard let binaryKey = binaryKeyPtr?.pointee else {
            throw ZcashError.rustDeriveUnifiedSpendingKey(
                lastErrorMessage(fallback: "`deriveUnifiedSpendingKey` failed with unknown error")
            )
        }

        return binaryKey.unsafeToUnifiedSpendingKey(network: networkType)
    }

    func deriveShieldedAddress(_ ufvk: String) throws -> String {
        guard !ufvk.containsCStringNullBytesBeforeStringEnding() else {
            throw ZcashError.rustDeriveShieldedAddress(
                "Input ufvk was empty - cannot derive Shielded Address"
            )
        }
        let address = zcashlc_derive_shielded_address_from_viewing_key([CChar](ufvk.utf8CString), networkType.networkId)
        guard let derived = String(validatingUTF8: address!) else {
            throw ZcashError.rustDeriveShieldedAddress (
                "Failed to convert shielded address to Swift String - cannot derive Shielded Address"
            )
        }
        return derived
    }

    func deriveSaplingSpendingKey(
        seed: [UInt8],
        accountIndex: Int32
    ) throws -> SaplingSpendingKey {

        let binaryKeyPtr = seed.withUnsafeBufferPointer { seedBufferPtr in
            zcashlc_derive_shielded_spending_key(
                seedBufferPtr.baseAddress, UInt(seed.count),
                accountIndex,
                networkType.networkId
            )
        }

        defer { zcashlc_free_binary_key(binaryKeyPtr) }

        guard let binaryKey = binaryKeyPtr?.pointee else {
            throw ZcashError.rustDeriveSaplingSpendingKey(
                lastErrorMessage(fallback: "`deriveSaplingSpendingKey` failed with unknown error")
            )
        }

        return binaryKey.unsafeToSaplingSpendingKey(network: networkType)
    }

    func zGetEncryptionAddress(
        seed: [UInt8]?,
        extsk: [UInt8]?,
        hdIndex: Int32,
        encryptionIndex: Int32,
        fromId: [UInt8]?,
        toId: [UInt8]?,
        returnSecret: Bool
    ) throws -> ChannelKeys {

        let seedLen: UInt = UInt(seed?.count ?? 0)
        let extskLen: UInt = UInt(extsk?.count ?? 0)
        let fromLen: UInt = UInt(fromId?.count ?? 0)
        let toLen: UInt = UInt(toId?.count ?? 0)

        @inline(__always)
        func ptrOrNil(_ array: [UInt8]?, _ buf: UnsafeRawBufferPointer) -> UnsafePointer<UInt8>? {
            guard let array, !array.isEmpty else { return nil }
            return buf.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }

        // (seed ?? []) etc. split out for readability / type-checking
        let seedArray = seed ?? []
        let extskArray = extsk ?? []
        let fromArray = fromId ?? []
        let toArray = toId ?? []

        let ffiChannelKeysPtr: UnsafeMutablePointer<FfiChannelKeys>? =
            seedArray.withUnsafeBytes { seedBuf -> UnsafeMutablePointer<FfiChannelKeys>? in
                extskArray.withUnsafeBytes { extskBuf -> UnsafeMutablePointer<FfiChannelKeys>? in
                    fromArray.withUnsafeBytes { fromBuf -> UnsafeMutablePointer<FfiChannelKeys>? in
                        toArray.withUnsafeBytes { toBuf -> UnsafeMutablePointer<FfiChannelKeys>? in

                            let seedPtr = ptrOrNil(seed, seedBuf)
                            let extskPtr = ptrOrNil(extsk, extskBuf)
                            let fromPtr = ptrOrNil(fromId, fromBuf)
                            let toPtr = ptrOrNil(toId, toBuf)

                            let result = zcashlc_z_get_encryption_address(
                                seedPtr,
                                seedLen,
                                extskPtr,
                                extskLen,
                                hdIndex,
                                encryptionIndex,
                                fromPtr,
                                fromLen,
                                toPtr,
                                toLen,
                                returnSecret
                            )

                            return result
                        }
                    }
                }
            }
        guard let ffiChannelKeysPtr else {
            throw ZcashError.rustGetEncryptionAddress( //placeholder
                lastErrorMessage(fallback: "`zGetEncryptionAddress` failed with unknown error")
            )
        }
        defer { zcashlc_free_channel_keys(ffiChannelKeysPtr) }

        // cheap copy, ptr to ptr... we can eliminate but want to avoid 
        let channelKeys = ffiChannelKeysPtr.pointee

        //TODO: I don't think we need to check pointers for validity in zcashlc_z_get_encryption_address
        // but we should double check that we don't, to be certain.  They should be valid for all non-optional retvals
        // also check that the above does not need called with 'ffiChannelKeysPtr?.pointee' as I see other places in code

        guard let address = String(validatingUTF8: channelKeys.address) else {
            // throw error, invalid string encoding for address
            // just mirroring TransparentAddress etc logic below, here
            //TODO: rename below properly, placeholder for now
            throw ZcashError.rustGetEncryptionAddress(
                lastErrorMessage(fallback: "`zGetEncryptionAddress` failed to encode address as string")
            )
        }

        let fullViewingKey =
            Array(UnsafeBufferPointer(start: channelKeys.full_viewing_key_ptr,
                                      count: Int(channelKeys.full_viewing_key_len)))
        let incomingViewingKey =
            Array(UnsafeBufferPointer(start: channelKeys.incoming_viewing_key_ptr,
                                      count: Int(channelKeys.incoming_viewing_key_len)))

        let spendingKey: [UInt8]?
        if channelKeys.spending_key_ptr != nil, channelKeys.spending_key_len > 0 {
            spendingKey =
                Array(UnsafeBufferPointer(start: channelKeys.spending_key_ptr,
                                          count: Int(channelKeys.spending_key_len)))
        } else {
            spendingKey = nil
        }

        return ChannelKeys(
            address: address,
            fullViewingKey: fullViewingKey,
            incomingViewingKey: incomingViewingKey,
            spendingKey: spendingKey
        )
    }

    func encryptVerusData(
        address: [UInt8],
        dataToEncrypt: [UInt8],
        returnSsk: Bool
    ) throws -> EncryptedPayload {
        let addressLen: UInt = UInt(address.count)
        let dataLen: UInt32 = UInt32(dataToEncrypt.count)

        @inline(__always)
        func ptrOrNil(_ array: [UInt8], _ buf: UnsafeRawBufferPointer) -> UnsafePointer<UInt8>? {
            guard !array.isEmpty else { return nil }
            return buf.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }

        let ffiEncryptedPayloadPtr: UnsafeMutablePointer<FfiEncryptedPayload>? =
            address.withUnsafeBytes { addressBuf -> UnsafeMutablePointer<FfiEncryptedPayload>? in
                dataToEncrypt.withUnsafeBytes { dataBuf -> UnsafeMutablePointer<FfiEncryptedPayload>? in
                    let addressPtr = ptrOrNil(address, addressBuf)
                    let dataPtr = ptrOrNil(dataToEncrypt, dataBuf)

                    return zcashlc_encrypt_vdata(
                        addressPtr,
                        addressLen,
                        dataPtr,
                        dataLen,
                        returnSsk
                    )
                }
            }

        guard let ffiEncryptedPayloadPtr else {
            throw ZcashError.rustEncryptVerusData(
                lastErrorMessage(fallback: "`encryptVerusData` failed with unknown error")
            )
        }
        defer { zcashlc_free_encrypted_payload(ffiEncryptedPayloadPtr) }

        let encryptedPayload = ffiEncryptedPayloadPtr.pointee

        let ephemeralPublicKey =
            Array(
                UnsafeBufferPointer(
                    start: encryptedPayload.ephemeral_public_key_ptr,
                    count: Int(encryptedPayload.ephemeral_public_key_len)
                )
            )

        let encryptedData =
            Array(
                UnsafeBufferPointer(
                    start: encryptedPayload.encrypted_data_ptr,
                    count: Int(encryptedPayload.encrypted_data_len)
                )
            )

        let symmetricKey: [UInt8]?
        if encryptedPayload.symmetric_key_ptr != nil, encryptedPayload.symmetric_key_len > 0 {
            symmetricKey =
                Array(
                    UnsafeBufferPointer(
                        start: encryptedPayload.symmetric_key_ptr,
                        count: Int(encryptedPayload.symmetric_key_len)
                    )
                )
        } else {
            symmetricKey = nil
        }

        return EncryptedPayload(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedData: encryptedData,
            symmetricKey: symmetricKey
        )
    }
    
    func decryptVerusData(
        incomingViewingKey: [UInt8]?,
        ephemeralPublicKey: [UInt8]?,
        dataToDecrypt: [UInt8],
        symmetricKey: [UInt8]?
    ) throws -> DecryptedData {
        let ivkLen: UInt = UInt(incomingViewingKey?.count ?? 0)
        let epkLen: UInt = UInt(ephemeralPublicKey?.count ?? 0)
        let dataLen: UInt32 = UInt32(dataToDecrypt.count)
        let sskLen: UInt = UInt(symmetricKey?.count ?? 0)

        @inline(__always)
        func ptrOrNil(_ array: [UInt8]?, _ buf: UnsafeRawBufferPointer) -> UnsafePointer<UInt8>? {
            guard let array, !array.isEmpty else { return nil }
            return buf.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }

        let ivkArray = incomingViewingKey ?? []
        let epkArray = ephemeralPublicKey ?? []
        let sskArray = symmetricKey ?? []

        let ffiByteBufferPtr: UnsafeMutablePointer<FfiByteBuffer>? =
            ivkArray.withUnsafeBytes { ivkBuf -> UnsafeMutablePointer<FfiByteBuffer>? in
                epkArray.withUnsafeBytes { epkBuf -> UnsafeMutablePointer<FfiByteBuffer>? in
                    dataToDecrypt.withUnsafeBytes { dataBuf -> UnsafeMutablePointer<FfiByteBuffer>? in
                        sskArray.withUnsafeBytes { sskBuf -> UnsafeMutablePointer<FfiByteBuffer>? in
                            let ivkPtr = ptrOrNil(incomingViewingKey, ivkBuf)
                            let epkPtr = ptrOrNil(ephemeralPublicKey, epkBuf)
                            let dataPtr = dataBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                            let sskPtr = ptrOrNil(symmetricKey, sskBuf)

                            return zcashlc_decrypt_vdata(
                                ivkPtr,
                                ivkLen,
                                epkPtr,
                                epkLen,
                                dataPtr,
                                dataLen,
                                sskPtr,
                                sskLen
                            )
                        }
                    }
                }
            }

        guard let ffiByteBufferPtr else {
            throw ZcashError.rustDecryptVerusData(
                lastErrorMessage(fallback: "`decryptVerusData` failed with unknown error")
            )
        }
        defer { zcashlc_free_byte_buffer_ptr(ffiByteBufferPtr) }

        let byteBuffer = ffiByteBufferPtr.pointee

        let decryptedBytes =
            Array(
                UnsafeBufferPointer(
                    start: byteBuffer.ptr,
                    count: Int(byteBuffer.len)
                )
            )

        return DecryptedData(
            data: decryptedBytes
        )
    }

    func deriveUnifiedFullViewingKey(from spendingKey: UnifiedSpendingKey) throws -> UnifiedFullViewingKey {
        let extfvk = try spendingKey.bytes.withUnsafeBufferPointer { uskBufferPtr -> UnsafeMutablePointer<CChar> in
            guard let extfvk = zcashlc_spending_key_to_full_viewing_key(
                uskBufferPtr.baseAddress,
                UInt(spendingKey.bytes.count),
                networkType.networkId
            ) else {
                throw ZcashError.rustDeriveUnifiedFullViewingKey(
                    lastErrorMessage(fallback: "`deriveUnifiedFullViewingKey` failed with unknown error")
                )
            }

            return extfvk
        }

        defer { zcashlc_string_free(extfvk) }

        guard let derived = String(validatingUTF8: extfvk) else {
            throw ZcashError.rustDeriveUnifiedFullViewingKeyInvalidDerivedKey
        }

        return UnifiedFullViewingKey(validatedEncoding: derived, account: spendingKey.account)
    }

    func getSaplingReceiver(for uAddr: UnifiedAddress) throws -> SaplingAddress {
        guard let saplingCStr = zcashlc_get_sapling_receiver_for_unified_address(
            [CChar](uAddr.encoding.utf8CString)
        ) else {
            throw ZcashError.rustGetSaplingReceiverInvalidAddress(uAddr)
        }

        defer { zcashlc_string_free(saplingCStr) }

        guard let saplingReceiverStr = String(validatingUTF8: saplingCStr) else {
            throw ZcashError.rustGetSaplingReceiverInvalidReceiver
        }

        return SaplingAddress(validatedEncoding: saplingReceiverStr)
    }

    func getTransparentReceiver(for uAddr: UnifiedAddress) throws -> TransparentAddress {
        guard let transparentCStr = zcashlc_get_transparent_receiver_for_unified_address(
            [CChar](uAddr.encoding.utf8CString)
        ) else {
            throw ZcashError.rustGetTransparentReceiverInvalidAddress(uAddr)
        }

        defer { zcashlc_string_free(transparentCStr) }

        guard let transparentReceiverStr = String(validatingUTF8: transparentCStr) else {
            throw ZcashError.rustGetTransparentReceiverInvalidReceiver
        }

        return TransparentAddress(validatedEncoding: transparentReceiverStr)
    }

    // MARK: Error Handling

    private func lastErrorMessage(fallback: String) -> String {
        let errorLen = zcashlc_last_error_length()
        defer { zcashlc_clear_last_error() }

        if errorLen > 0 {
            let error = UnsafeMutablePointer<Int8>.allocate(capacity: Int(errorLen))
            defer { error.deallocate() }

            zcashlc_error_message_utf8(error, errorLen)
            if let errorMessage = String(validatingUTF8: error) {
                return errorMessage
            } else {
                return fallback
            }
        } else {
            return fallback
        }
    }
}
