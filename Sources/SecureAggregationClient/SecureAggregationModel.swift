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
    private(set) var state: SecureAggregationRoundState<Value> = .waiting
    
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
        
    func saveSetupData(config: SAConfiguration<Value>) throws {
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
    
    struct SharesWrapper: Codable {
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
        
        // MARK: Assertions
        if let error = checkValidity(round0FinishedState: currentState) {
            throw error
        }
        
        // MARK: Sample b_u
        let b_u_privateKey = SAPubKeyCurve.KeyAgreement.PrivateKey()
        
        // MARK: Generate t-out-of-|U1| shares of s_u_SK and b_u
        // common parameters for both sharing-processes:
        let threshold = currentState.config.threshold
        let numberOfShares = currentState.U1.count
        // create shares:
        let s_u_privateKeyShares = try createShares(for: currentState.generatedKeyPairs.s_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)
        let b_u_secretKeyShared = try  createShares(for: b_u_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)
        
        // MARK: encrypt s_uv_SK, b_uv, u.id, v.id with shared key of u & v => e_uv
        let ownUserId = currentState.userID
        let encryptedAndWrappedSharesReadyForTransport = try encryptAndWrapShares(currentState: currentState,
                                                                              s_u_privateKeyShares: s_u_privateKeyShares,
                                                                              b_u_secretKeyShared: b_u_secretKeyShared,
                                                                              ownUserId: ownUserId)
        // MARK: Save all messages received & values generated
        #warning("TODO: save all messages received & values generated (where later needed)")
        try state.advance(to: .round1(Round1State(previousState: currentState, b_u: Data())))
        // return
        return Round1ClientData(encryptedShares: encryptedAndWrappedSharesReadyForTransport)
    }
    
    /// Creates t-out-of-n shares
    func createShares(for data: Data, threshold: Int, numberOfShares: Int) throws -> [Secret.Share] {
        return try Secret(data: data, threshold: threshold, shares: numberOfShares).split()
    }
    
    /// Checks if round0Finished state is not corrupted and round1 can start
    ///
    /// - Returns: SecureAggregationError if round1 cannot start, nil if Round0FinishedState is valid
    func checkValidity(round0FinishedState: Round0FinishedState<Value>) -> SecureAggregationError? {
        let otherUserPublicKeys = round0FinishedState.otherUserPublicKeys

        // Assert |U1| >= t
        guard uniqueRemainingUsersOverThreshold(userIDs: otherUserPublicKeys.map { $0.userID },
                                                currentState: round0FinishedState) else {
            return SecureAggregationError.protocolAborted(reason: .tThresholdUndercut)
        }
        // Assert all public key pairs are different
        guard otherUserPublicKeys.allUnique(\.c_publicKey.rawRepresentation) &&
                otherUserPublicKeys.allUnique(\.s_publicKey.rawRepresentation) else {
            return SecureAggregationError.protocolAborted(reason: .securityViolation(description: "Public keys from Round0 were not distinct"))
        }
        // Everything ok => return nil
        return nil
    }
    
    func uniqueRemainingUsersOverThreshold(userIDs: [UserID], currentState: SetupState<Value>) -> Bool {
        return Set(userIDs).count >= currentState.config.threshold
    }
    
    /// Wraps, encrypts and wraps the secret shares again with UserIDs of pariticpating parties
    func encryptAndWrapShares(currentState round0FinishedState: Round0FinishedState<Value>,
                                          s_u_privateKeyShares: [Secret.Share],
                                          b_u_secretKeyShared: [Secret.Share],
                                          ownUserId: UserID) throws -> [EncryptedShare] {
        return try zip(round0FinishedState.otherUserPublicKeys, zip(s_u_privateKeyShares, b_u_secretKeyShared)).map {
            (otherUserPublicKeyWrapper: PublicKeysOfUser,
             shares:(s_uv_share: Secret.Share, b_uv_share: Secret.Share)) -> EncryptedShare in
            // Calculate key agreement with user v
            let otherUserID = otherUserPublicKeyWrapper.userID
            let c_v_publicKey = otherUserPublicKeyWrapper.c_publicKey
            let c_u_privateKey = round0FinishedState.generatedKeyPairs.c_privateKey
            let sharedSecretWithV = try c_u_privateKey.sharedSecretFromKeyAgreement(with: c_v_publicKey)
            let symmectricKeyWithV = sharedSecretWithV.hkdfDerivedSymmetricKey(using: SA_HKDF_HashFunction.self,
                                                                               salt: round0FinishedState.config.salt,
                                                                               sharedInfo: Data(),
                                                                               outputByteCount: 256)
            // encrypt
            let dataToBeEncrypted = SharesWrapper(u: ownUserId,
                                                                     v: otherUserID,
                                                                     s_uv_privateKeyShare: shares.s_uv_share,
                                                                     b_uv_Share: shares.b_uv_share)
            let data = try JSONEncoder().encode(dataToBeEncrypted)
            let encryptedData = try SASymmetricCipher.seal(data, using: symmectricKeyWithV)
            return EncryptedShare(e_uv: encryptedData,
                                  u: ownUserId,
                                  v: otherUserID)
        }
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
