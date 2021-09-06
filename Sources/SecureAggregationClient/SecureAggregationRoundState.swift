//
//  File.swift
//  
//
//  Created by stephan on 17.08.21.
//

import Foundation
import SecureAggregationCore

/// State gets set with the results collected from the Server
enum SecureAggregationRoundState<Value: SAWrappedValue> {
    case aborted
    case waiting
    case login(_: LoginState)
    case setup(_: SetupState<Value>)
    case round0(_: Round0State<Value>)
    case round0Finished(_: Round0FinishedState<Value>)
    case round1(_: Round1State<Value>)
    case round1Finished(_: Round1FinishedState<Value>)
    case round2(_: Round2State<Value>)
    case round2Finished(_: Round2FinishedState<Value>)
//    case round3 (all red parts skipped for now)
    case round4(_:Round4State<Value>)
}

class LoginState {
    let ownUserID: UserID
    
    init(userID: UserID) {
        self.ownUserID = userID
    }
    
    init(copyConstructor other: LoginState) {
        self.ownUserID = other.ownUserID
    }
}

class SetupState<Value: SAWrappedValue>: LoginState {
    let config: SAConfiguration<Value>
    
    init(previousState: LoginState, config: SAConfiguration<Value>) {
        self.config = config
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: SetupState) { // TODO: warum funktioniert hier convenience-init nicht?
        self.config = other.config
        super.init(copyConstructor: other)
//        self.init(previousState: other, config: other.config)
    }
}

struct GeneratedKeyPairs {
    let c_privateKey: SAPubKeyCurve.KeyAgreement.PrivateKey
    var c_publicKey: SAPubKeyCurve.KeyAgreement.PublicKey {
        c_privateKey.publicKey
    }
    let s_privateKey: SAPubKeyCurve.KeyAgreement.PrivateKey
    var s_publicKey: SAPubKeyCurve.KeyAgreement.PublicKey {
        s_privateKey.publicKey
    }

}

class Round0State<Value: SAWrappedValue>: SetupState<Value> {
    let generatedKeyPairs: GeneratedKeyPairs
    
    init(previousState: SetupState<Value>, generatedKeyPairs: GeneratedKeyPairs) {
        self.generatedKeyPairs = generatedKeyPairs
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round0State) { // TODO: warum funktioniert hier convenience-init nicht?
        self.generatedKeyPairs = other.generatedKeyPairs
        super.init(copyConstructor: other)
//        self.init(previousState: other, generatedKeyPairs: other.generatedKeyPairs)
    }
}

/// Public keys of the user with `UserID` `userID`
struct PublicKeysOfUser {
    /// User who ones the private keys corresponding to the public keys
    let userID: UserID
    let c_publicKey: SAPubKeyCurve.KeyAgreement.PublicKey
    let s_publicKey: SAPubKeyCurve.KeyAgreement.PublicKey
}

class Round0FinishedState<Value: SAWrappedValue>: Round0State<Value> {
    let otherUserPublicKeys: [PublicKeysOfUser]
    var U1: [UserID] {
        otherUserPublicKeys.map { $0.userID }
    }
    
    init(previousState: Round0State<Value>, otherUserPublicKeys: [PublicKeysOfUser]) {
        self.otherUserPublicKeys = otherUserPublicKeys
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round0FinishedState) { // TODO: warum funktioniert hier convenience-init nicht?
        self.otherUserPublicKeys = other.otherUserPublicKeys
        super.init(copyConstructor: other)
        //        self.init(previousState: other, otherUserPublicKeys: other.otherUserPublicKeys)
    }
}

class Round1State<Value: SAWrappedValue>: Round0FinishedState<Value> {
    typealias B_U_Type = Data
    let b_u: B_U_Type
    
    init(previousState: Round0FinishedState<Value>, b_u: B_U_Type) {
        self.b_u = b_u
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round1State) { // TODO: warum funktioniert hier convenience-init nicht?
        self.b_u = other.b_u
        super.init(copyConstructor: other)
        // self.init(previousState: other, b_u: other.b_u)
    }
}

/// Encrypted share from user `u` to user `v`
struct EncryptedShare {
    /// Encrypted shares (`EncryptedRound1ClientDataWrapper`)
    var e_uv: SASymmetricCipher.SealedBox
    /// User that encrypted the shares
    var u: UserID
    /// Destination for the encrypted shares
    var v: UserID
}

class Round1FinishedState<Value: SAWrappedValue>: Round1State<Value> {
    let encryptedSharesForMe: [EncryptedShare]
    
    init(previousState: Round1State<Value>, encryptedShares: [EncryptedShare]) {
        self.encryptedSharesForMe = encryptedShares
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round1FinishedState) { // TODO: warum funktioniert hier convenience-init nicht?
        self.encryptedSharesForMe = other.encryptedSharesForMe
        super.init(copyConstructor: other)
//        self.init(previousState: other, encryptedCiphertexts: other.encryptedCiphertextsForMe)
    }
}

class Round2State<Value: SAWrappedValue>: Round1FinishedState<Value> {
    init(previousState: Round1FinishedState<Value>) {
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round2State) {
        super.init(copyConstructor: other)
    }
}

class Round2FinishedState<Value: SAWrappedValue>: Round2State<Value> {
    let round2RemainingUsers: [UserID]
    
    var U3: [UserID] {
        round2RemainingUsers
    }
    
    init(previousState: Round2State<Value>, remainingUsers: [UserID]) {
        self.round2RemainingUsers = remainingUsers
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round2FinishedState) {
        self.round2RemainingUsers = other.round2RemainingUsers
        super.init(copyConstructor: other)
    }
}

class Round4State<Value: SAWrappedValue>: Round2FinishedState<Value> {
    init(previousState: Round2FinishedState<Value>) {
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round4State) {
        super.init(copyConstructor: other)
    }
}
