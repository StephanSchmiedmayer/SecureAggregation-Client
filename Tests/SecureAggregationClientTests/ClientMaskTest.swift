//
//  File.swift
//  
//
//  Created by stephan on 07.10.21.
//

import Foundation
import XCTest
@testable import SecureAggregationCore
import CryptoKit

final class ClientMaskTest: XCTestCase {
    let modulus = 1000
    
    func testGeneratePrivatekey() {
        print(SAPubKeyCurve.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString())
    }
    
    func testKeys() throws {
        let privateKeyRawRepresentation = Data(base64Encoded: "CNgomuI4rzMBZORr3Kpv0lgYsvJyVLJUfCEFtEQe2V8=")!
        let privateKey = try! SAPubKeyCurve.KeyAgreement.PrivateKey(rawRepresentation: privateKeyRawRepresentation)
        print(privateKey)
        print("public key: \(privateKey.publicKey)")
        let sharedSecret = try! privateKey.sharedSecretFromKeyAgreement(with: privateKey.publicKey)
        print(sharedSecret)
        print(sharedSecret.hashValue)
        print(sharedSecret.hashValue)
        let mask = try SAInt.mask(sharedSecret: sharedSecret, salt: Data(), mod: modulus)
        print(mask)

    }
    
    func testMask() throws {
        let value = try privateKeyStringToSAValue(base64encodedPrivate: "qNoyh5OKJ2XBSERYFjPOPoollxqAvnYFNP/s5NUp0Xg=", modulus: modulus)
        
        print(value?.description ?? "Failed to load SAInt from base64encodedString")
        XCTAssertEqual(value, SAInt(986, mod: modulus))
    }
    
    func testCreatePrivateKeyData() {
        print(SAPubKeyCurve.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString())
    }
    
    func privateKeyStringToSAValue(base64encodedPrivate base64encodedString: String, modulus: Int) throws -> SAInt? {
        guard let privateKeyRawRepresentation = Data(base64Encoded: base64encodedString),
              let privateKey = try? SAPubKeyCurve.KeyAgreement.PrivateKey(rawRepresentation: privateKeyRawRepresentation),
              let sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: privateKey.publicKey)
        else {
            return nil
        }
        return try SAInt.mask(sharedSecret: sharedSecret, salt: Data(), mod: modulus)
    }
}
