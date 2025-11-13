// Bech32.swift
// Decodes Bech32

import Foundation

public enum Bech32DecodingError: Error {
  case invalidCharacter(Character)
  case mixedCase
  case noSeparator
  case invalidSeparatorPosition
  case hrpTooShort
  case dataTooShort
  case wrongVariantBech32m
  case checksumMismatch
  case invalidPadding
}

public struct Bech32 {
  private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
  private static let gen: [UInt32] = [
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
  ]
  private static let BECH32_CONST: UInt32 = 1
  private static let BECH32M_CONST: UInt32 = 0x2bc830a3

  private static let revMap: [UInt8] = {
    var map = [UInt8](repeating: 255, count: 128)
    for (i, c) in charset.enumerated() {
      map[Int(c.asciiValue!)] = UInt8(i)
      map[Int(Character(String(c).uppercased()).asciiValue!)] = UInt8(i)
    }
    return map
  }()

  static func decode(_ s: String) throws -> (hrp: String, data: [UInt8]) {
    let hasUpper = s.contains { $0.isUppercase }
    let hasLower = s.contains { $0.isLowercase }
    if hasUpper && hasLower { throw Bech32DecodingError.mixedCase }

    guard let pos = s.lastIndex(of: "1") else { throw Bech32DecodingError.noSeparator }
    let sep = s.distance(from: s.startIndex, to: pos)
    if sep < 1 { throw Bech32DecodingError.hrpTooShort }
    if s.count - sep - 1 < 6 { throw Bech32DecodingError.dataTooShort }

    let hrp = String(s[..<pos]).lowercased()

    let dataPart = s[s.index(after: pos)...]
    var values = [UInt8]()
    values.reserveCapacity(dataPart.count)
    for ch in dataPart {
      guard ch.unicodeScalars.allSatisfy({ $0.value < 128 }) else {
        throw Bech32DecodingError.invalidCharacter(ch)
      }
      let idx = revMap[Int(ch.asciiValue!)]
      if idx == 255 { throw Bech32DecodingError.invalidCharacter(ch) }
      values.append(idx)
    }

    guard verifyChecksum(hrp: hrp, data: values) else {
      throw Bech32DecodingError.checksumMismatch
    }
    let const = polymod(hrpExpand(hrp) + values)
    if const == BECH32M_CONST { throw Bech32DecodingError.wrongVariantBech32m }

    let payload5 = Array(values.dropLast(6))

    guard let bytes = convertBits(payload5, from: 5, to: 8, pad: false) else {
      throw Bech32DecodingError.invalidPadding
    }

    return (hrp, bytes)
  }

  // Internals
  private static func hrpExpand(_ hrp: String) -> [UInt8] {
    let bytes = hrp.utf8.map { $0 }
    var res: [UInt8] = bytes.map { $0 >> 5 }
    res.append(0)
    res.append(contentsOf: bytes.map { $0 & 0x1f })
    return res
  }

  private static func polymod(_ values: [UInt8]) -> UInt32 {
    var chk: UInt32 = 1
    for v in values {
      let top = chk >> 25
      chk = (chk & 0x1ffffff) << 5 ^ UInt32(v)
      for i in 0..<5 {
        if ((top >> i) & 1) != 0 {
          chk ^= gen[i]
        }
      }
    }
    return chk
  }

  private static func verifyChecksum(hrp: String, data: [UInt8]) -> Bool {
    polymod(hrpExpand(hrp) + data) == BECH32_CONST || polymod(hrpExpand(hrp) + data) == BECH32M_CONST
  }

  private static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8]? {
    var acc = 0
    var bits = 0
    let maxv = (1 << to) - 1
    var ret = [UInt8]()
    for value in data {
      if value >> from != 0 { return nil }
      acc = (acc << from) | Int(value)
      bits += from
      while bits >= to {
        bits -= to
        ret.append(UInt8((acc >> bits) & maxv))
      }
    }
    if pad {
      if bits > 0 { ret.append(UInt8((acc << (to - bits)) & maxv)) }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
      return nil
    }
    return ret
  }
}
