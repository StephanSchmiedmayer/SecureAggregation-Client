//
//  File.swift
//  
//
//  Created by stephan on 04.09.21.
//

import Foundation
import XCTest
import SecureAggregationCore
@testable import SecureAggregationClient

//protocol MockServerMessage {
//    associatedtype ValueType: SAWrappedValue
//    var userID: UserID { get }
//    var config: SAConfiguration { get }
//    var round0ServerData: SecureAggregationModel<ValueType>.Round0ServerData { get }
//}
//
//struct MockServerModel {
//
//}

final class SecureAggregationModelTests: XCTestCase {
//    func generateRandomPublicKey() -> SAPubKeyCurve.KeyAgreement.PublicKey {
//        SAPubKeyCurve.KeyAgreement.PrivateKey().publicKey
//    }
//
//    func generateRandomPublicKeysOfUser(userIDs: Range<UserID>) -> [PublicKeysOfUser] {
//        userIDs.map { id in
//            PublicKeysOfUser(userID: id,
//                             c_publicKey: generateRandomPublicKey(),
//                             s_publicKey: generateRandomPublicKey())
//        }
//    }
    
//    struct MockServerMessages: MockServerMessage {
//        typealias ValueType = SAInt
//
//        let userID = 0
//        let config = SAConfiguration(numberOfUsers: 10, threshold: 5, modulus: 100, salt: "LeagueOfLegends".data(using: .utf8)!)
//        let round0ServerData = SecureAggregationModel<SAInt>.Round0ServerData(collectedData: [
//
//        ])
//
//    }
    
    func testInitialization() {
        let model = SecureAggregationModel(value: SAInt(10))
        guard case .waiting = model.state else {
            XCTFail("Initial state not waiting")
            return
        }
    }
    
    func testLogin() {
        let userID = 13
        let model = SecureAggregationModel(value: SAInt(10))
        XCTAssertNoThrow(try model.saveLoginData(userID: userID), "SaveLoginData threw")
        guard case .login(let loginState) = model.state else {
            XCTFail("Unexpected state after login")
            return
        }
        XCTAssertEqual(loginState.ownUserID, userID)
    }
    
    func testRound1() {
        let model = SecureAggregationModel(value: SAInt(10))
        do {
            try model.saveLoginData(userID: 10)
            try model.saveSetupData(config: SAConfiguration(numberOfUsers: 10, threshold: 1, modulus: 133, salt: "LeageOfLegens".data(using: .utf8)!))
            let _ = try model.round0()
            try model.processRound0Data(SecureAggregationModel<SAInt>.Round0ServerData(collectedData: [Round0.PublicKeysOfUser(userID: 5, c_publicKey: SAPubKeyCurve.KeyAgreement.PrivateKey().publicKey, s_publicKey: SAPubKeyCurve.KeyAgreement.PrivateKey().publicKey)]))
        } catch is SecureAggregationError {
            XCTFail("SecureAggregationError")
        } catch {
            XCTFail("Unexpected Error")
        }
    }
}
