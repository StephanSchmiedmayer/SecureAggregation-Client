//
//  File.swift
//  
//
//  Created by stephan on 17.08.21.
//

import Foundation
import Combine
import CryptoKit
import SecureAggregationCore
import ShamirSecretShare

class SecureAggregationModel<Value: SAWrappedValue> {
    private(set) var state: SecureAggregationRoundState = .waiting
    
    private let dispatchQueue = DispatchQueue(label: "SecureAggregationModel") // TODO: actually use
    
    /// The value to aggregate
    private var value: Value
    
    init(value: Value) {
        self.value = value
    }
    
    func saveLoginData(userID: UserID) throws {
        guard case .waiting = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        try state.advance(to: .login(LoginState(userID: userID)))
    }
        
    func saveSetupData(config: SAConfiguration) throws {
        guard case .login(let loginState) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        try state.advance(to: .setup(SetupState(previousState: loginState, config: config)))
    }
    
    // MARK: - Round 0
    // MARK: Client -> Server
    struct Round0ClientData {
        let publicKeyInformation: PublicKeysOfUser
    }
    
    /// Get client message for round 0
    func round0() throws -> Round0ClientData  {
        guard case .setup(let setupState) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        // generate 2 key pairs
        let generatedKeys = GeneratedKeyPairs(c_privateKey: SAPubKeyCurve.KeyAgreement.PrivateKey(), s_privateKey: SAPubKeyCurve.KeyAgreement.PrivateKey())
        let round0State = Round0State(previousState: setupState, generatedKeyPairs: generatedKeys)
        try state.advance(to: .round0(round0State))
        // send public keys to server
        return Round0ClientData(publicKeyInformation: PublicKeysOfUser(userID: round0State.userID, c_publicKey: round0State.generatedKeyPairs.c_publicKey, s_publicKey: round0State.generatedKeyPairs.s_publicKey))
    }
    
    // MARK: Server -> Client
    struct Round0ServerData {
        let collectedData: [PublicKeysOfUser]
    }
    
    func processRound0Data(_ serverMessage: Round0ServerData) throws {
        guard case .round0(let round0State) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        let otherUserPublicKeys = serverMessage.collectedData.filter { publicKeysOfUser in
            publicKeysOfUser.userID != round0State.userID
        }
        
        try state.advance(to: .round0Finished(Round0FinishedState(previousState: round0State, otherUserPublicKeys: otherUserPublicKeys)))
    }
    
    // MARK: - Round 1
    // MARK: Client -> Server
    struct Round1ClientData {        
        var encryptedShares: [EncryptedShare]
    }
    
    struct EncryptedRound1ClientDataWrapper {
        var u: UserID
        var v: UserID
        var s_uv_privateKeyShare: Secret.Share
        var b_uv_Share: Secret.Share
    }
    
    
    func round1() throws -> Round1ClientData {
        guard case let .round0Finished(currentState) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        // here:
        // u ^= self
        // v ^= other User
        
        let otherUserPublicKeys = currentState.otherUserPublicKeys
        // Assert |U1| >= t
        guard Set(otherUserPublicKeys.map { $0.userID }).count >= currentState.config.threshold else {
            throw SecureAggregationError.protocolAborted(reason: .tThresholdUndercut)
        }
        // Assert all public key pairs are different
        guard otherUserPublicKeys.allUnique(\.c_publicKey.rawRepresentation) &&
                otherUserPublicKeys.allUnique(\.s_publicKey.rawRepresentation) else {
            throw SecureAggregationError.protocolAborted(reason: .securityViolation(description: "Public keys from Round0 were not distinct"))
        }
        // Sample b_u
        let b_u_privateKey = SAPubKeyCurve.KeyAgreement.PrivateKey()
        // Generate t-out-of-|U1| shares of s_u_SK and b_u
        // common parameters for both sharing-processes:
        let threshold = currentState.config.threshold
        let numberOfShares = currentState.U1.count
        // create shares:
        let s_u_privateKeyShamirSecretShareProducer = try Secret(data: currentState.generatedKeyPairs.s_privateKey.rawRepresentation,
                                                   threshold: threshold,
                                                   shares: numberOfShares)
        let s_u_privateKeyShares = try s_u_privateKeyShamirSecretShareProducer.split()
        let b_u_privateKeyShamirSecretShareProducer = try Secret(data: b_u_privateKey.rawRepresentation,
                                                          threshold: threshold,
                                                          shares: numberOfShares)
        let b_u_secretKeyShared = try b_u_privateKeyShamirSecretShareProducer.split()
        // encrypt s_uv_SK, b_uv, u.id, v.id with shared key of u & v => e_uv
        let ownUserId = currentState.userID
        let encryptedAndWrappedSharesReadyForTransport = try zip(otherUserPublicKeys, zip(s_u_privateKeyShares, b_u_secretKeyShared)).map {
            (otherUserPublicKeyWrapper: PublicKeysOfUser,
             shares:(s_uv_share: Secret.Share, b_uv_share: Secret.Share)) -> EncryptedShare in
            // Calculate key agreement with user v
            let otherUserID = otherUserPublicKeyWrapper.userID
            let c_v_publicKey = otherUserPublicKeyWrapper.c_publicKey
            let c_u_privateKey = currentState.generatedKeyPairs.c_privateKey
            let sharedSecretWithV = try c_u_privateKey.sharedSecretFromKeyAgreement(with: c_v_publicKey)
            let symmectricKeyWithV = sharedSecretWithV.hkdfDerivedSymmetricKey(using: SA_HKDF_HashFunction.self,
                                                                               salt: currentState.config.salt,
                                                                               sharedInfo: Data(),
                                                                               outputByteCount: 256)
            var dataToBeEncrypted = EncryptedRound1ClientDataWrapper(u: ownUserId,
                                                                     v: otherUserID,
                                                                     s_uv_privateKeyShare: shares.s_uv_share,
                                                                     b_uv_Share: shares.b_uv_share)
            #warning("TODO: mit JSON-endcoding ersetzen")
            let data = withUnsafeBytes(of: &dataToBeEncrypted) { Data($0) } // TODO: richtig so?
            let encryptedData = try SASymmetricCipher.seal(data, using: symmectricKeyWithV)
            return EncryptedShare(e_uv: encryptedData,
                                                    u: ownUserId,
                                                    v: otherUserID)
        }
        // Save all messages received & values generated
        #warning("TODO: save all messages received & values generated (where later needed)")
        
        // "Send" e_uu to the server
        return Round1ClientData(encryptedShares: encryptedAndWrappedSharesReadyForTransport)
    }
    
    // MARK: Server -> Client
    struct Round1ServerData {
        let encryptedServerMessagesForMe: [Round1ClientData]
    }
    
    func processRound1Data(_ serverMessage: Round1ServerData) throws {
        guard case .round1(let round1State) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        #warning("check validitiy of Server data")
//        try state.advance(to: .round1Finished(Round1FinishedState(previousState: round1State, encryptedCiphertexts: serverMessage.encryptedServerMessagesForMe)))
    }

}
