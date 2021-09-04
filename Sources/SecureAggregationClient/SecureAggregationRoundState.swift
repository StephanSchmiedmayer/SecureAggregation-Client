//
//  File.swift
//  
//
//  Created by stephan on 17.08.21.
//

import Foundation
import SecureAggregationCore

/// State gets set with the results collected from the Server
enum SecureAggregationRoundState {
    case aborted
    case waiting
    case login(_: LoginState)
    case setup(_: SetupState)
    case round0(_: Round0State)
    case round0Finished(_: Round0FinishedState)
    case round1(_: Round1State)
    case round1Finished(_: Round1FinishedState)
    case round2(_: Round2State)
    case round2Finished(_: Round2FinishedState)
//    case round3 (all red parts skipped for now)
    case round4(_:Round4State)
}

class LoginState {
    let userID: UserID
    
    init(userID: UserID) {
        self.userID = userID
    }
    
    init(copyConstructor other: LoginState) {
        self.userID = other.userID
    }
}

class SetupState: LoginState {
    let config: SAConfiguration
    
    init(previousState: LoginState, config: SAConfiguration) {
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

class Round0State: SetupState {
    let generatedKeyPairs: GeneratedKeyPairs
    
    init(previousState: SetupState, generatedKeyPairs: GeneratedKeyPairs) {
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

class Round0FinishedState: Round0State {
    let otherUserPublicKeys: [PublicKeysOfUser]
    var U1: [UserID] {
        otherUserPublicKeys.map { $0.userID }
    }
    
    init(previousState: Round0State, otherUserPublicKeys: [PublicKeysOfUser]) {
        self.otherUserPublicKeys = otherUserPublicKeys
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round0FinishedState) { // TODO: warum funktioniert hier convenience-init nicht?
        self.otherUserPublicKeys = other.otherUserPublicKeys
        super.init(copyConstructor: other)
        //        self.init(previousState: other, otherUserPublicKeys: other.otherUserPublicKeys)
    }
}

class Round1State: Round0FinishedState {
    typealias B_U_Type = Data
    let b_u: B_U_Type
    
    init(previousState: Round0FinishedState, b_u: B_U_Type) {
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

class Round1FinishedState: Round1State {
    typealias EncryptedCiphertextsForMeType = Data
    let encryptedCiphertextsForMe: [EncryptedCiphertextsForMeType]
    
    init(previousState: Round1State, encryptedCiphertexts: [EncryptedCiphertextsForMeType]) {
        self.encryptedCiphertextsForMe = encryptedCiphertexts
        super.init(copyConstructor: previousState)
    }
    
    init(copyConstructor other: Round1FinishedState) { // TODO: warum funktioniert hier convenience-init nicht?
        self.encryptedCiphertextsForMe = other.encryptedCiphertextsForMe
        super.init(copyConstructor: other)
//        self.init(previousState: other, encryptedCiphertexts: other.encryptedCiphertextsForMe)
    }
}

class Round2State {
    
}

class Round2FinishedState {
    
}

class Round4State {
    
}
