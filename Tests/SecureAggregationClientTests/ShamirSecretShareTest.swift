//
//  File.swift
//  
//
//  Created by stephan on 05.10.21.
//

import Foundation
import SwiftySSS
import XCTest
@testable import SecureAggregationCore
@testable import SecureAggregationClient

final class SwiftySSSTest: XCTestCase {

    let numberOfShares = 3 // TODO: richtig? (pretty sure it is)
    let threshold = 2
    let modulus = 100
    
    func testRound4() throws {
        let b_u1_privateKey = SAPubKeyCurve.KeyAgreement.PrivateKey()
        let b_u2_privateKey = SAPubKeyCurve.KeyAgreement.PrivateKey()
        let b_u3_privateKey = SAPubKeyCurve.KeyAgreement.PrivateKey()

        let b_u1_secretKeyShared = try SecureAggregationModel<SAInt>(value: SAInt(1, mod: 1)).createShares(for: b_u1_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)
        let b_u2_secretKeyShared = try SecureAggregationModel<SAInt>(value: SAInt(1, mod: 1)).createShares(for: b_u2_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)
        let b_u3_secretKeyShared = try SecureAggregationModel<SAInt>(value: SAInt(1, mod: 1)).createShares(for: b_u3_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)

        let b_u1_sharedSecret = try b_u1_privateKey.sharedSecretFromKeyAgreement(with: b_u1_privateKey.publicKey)
        let b_u2_sharedSecret = try b_u2_privateKey.sharedSecretFromKeyAgreement(with: b_u2_privateKey.publicKey)
        let b_u3_sharedSecret = try b_u3_privateKey.sharedSecretFromKeyAgreement(with: b_u3_privateKey.publicKey)
        
        let ownMask1 = try SAInt.mask(sharedSecret: b_u1_sharedSecret, salt: Data(), mod: modulus)
        let ownMask2 = try SAInt.mask(sharedSecret: b_u2_sharedSecret, salt: Data(), mod: modulus)
        let ownMask3 = try SAInt.mask(sharedSecret: b_u3_sharedSecret, salt: Data(), mod: modulus)
        
        print("\(ownMask1), \(ownMask2), \(ownMask3)")

        let ownMasksReconstructed = try [
            b_u1_secretKeyShared[1...2],
            b_u2_secretKeyShared[1...2],
            b_u3_secretKeyShared[1...2],
        ]
            .map {
                Array($0)
            }
            .map { shares in
                try Secret.combine(shares: shares)
            }.map { privateKeyData in
                try SAPubKeyCurve.KeyAgreement.PrivateKey.init(rawRepresentation: privateKeyData)
            }.map { privateKey in
                try privateKey.sharedSecretFromKeyAgreement(with: privateKey.publicKey)
            }.map { secret in
                try SAInt.mask(sharedSecret: secret, salt: Data(), mod: self.modulus)
            }
        print(ownMasksReconstructed)
        XCTAssertEqual([ownMask1, ownMask2, ownMask3], ownMasksReconstructed)
    }
}
