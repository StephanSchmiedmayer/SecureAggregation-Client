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
import SwiftySSS
import SwiftUI

class SecureAggregationModel<Value: SAWrappedValue>: ObservableObject {
    @Published private(set) var state: SecureAggregationRoundState<Value> = .waiting // TODO: make completely private
    
    private let dispatchQueue = DispatchQueue(label: "SecureAggregationModel") // TODO: actually use
    
    /// The value to aggregate
    let value: Value
    
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
    /// Get client message for round 0
    func round0() throws -> Model.Round0.ClientData  {
        guard case .setup(let setupState) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        // generate 2 key pairs
        let generatedKeys = GeneratedKeyPairs(c_privateKey: SAPubKeyCurve.KeyAgreement.PrivateKey(),
                                              s_privateKey: SAPubKeyCurve.KeyAgreement.PrivateKey())
        let round0State = Round0State(previousState: setupState, generatedKeyPairs: generatedKeys)
        try state.advance(to: .round0(round0State))
        // send public keys to server
        return Model.Round0.ClientData(publicKeyInformation: Model.PublicKeysOfUser(userID: round0State.ownUserID,
                                                                                    c_publicKey: round0State.generatedKeyPairs.c_publicKey,
                                                                                    s_publicKey: round0State.generatedKeyPairs.s_publicKey))
    }
    
    // MARK: Server -> Client
    func processRound0Data(_ serverMessage: Model.Round0.ServerData) throws {
        guard case .round0(let round0State) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        let otherUserPublicKeys = serverMessage.collectedData.filter { publicKeysOfUser in
            publicKeysOfUser.userID != round0State.ownUserID
        }
        
        try state.advance(to: .round0Finished(Round0FinishedState(previousState: round0State, otherUserPublicKeys: otherUserPublicKeys)))
    }
    
    // MARK: - Round 1
    // MARK: Client -> Server
    func round1() throws -> Model.Round1.ClientData {
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
        let numberOfShares = currentState.U1.count // TODO: - 1 weil man selbst keine Share braucht
        // create shares:
        let s_u_privateKeyShares = try createShares(for: currentState.generatedKeyPairs.s_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)
        let b_u_secretKeyShared = try createShares(for: b_u_privateKey.rawRepresentation, threshold: threshold, numberOfShares: numberOfShares)
        
        // TODO: save own b_uv for later sending to the server
        
        // MARK: encrypt s_uv_SK, b_uv, u.id, v.id with shared key of u & v => e_uv
        let ownUserId = currentState.ownUserID
        let encryptedAndWrappedSharesReadyForTransport = try encryptAndWrapShares(
            currentState: currentState,
            s_u_privateKeyShares: s_u_privateKeyShares,
            b_u_secretKeyShared: b_u_secretKeyShared,
            ownUserId: ownUserId)
        // MARK: Save all messages received & values generated
        // TODO: save all messages received & values generated (where later needed)?
        try state.advance(to: .round1(Round1State(previousState: currentState,
                                                  b_u_privateKey: b_u_privateKey)))
        // return
        return Model.Round1.ClientData(encryptedShares: encryptedAndWrappedSharesReadyForTransport)
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
        guard uniqueRemainingUsersOverThreshold(userIDs: round0FinishedState.U1,
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
                                          ownUserId: UserID) throws -> [Model.EncryptedShare] {
        return try zip(round0FinishedState.otherUserPublicKeys, zip(s_u_privateKeyShares, b_u_secretKeyShared)).map {
            (otherUserPublicKeyWrapper: Model.PublicKeysOfUser,
             shares:(s_uv_share: Secret.Share, b_uv_share: Secret.Share)) -> Model.EncryptedShare in
            // Calculate key agreement with user v
            let otherUserID = otherUserPublicKeyWrapper.userID
            let c_v_publicKey = otherUserPublicKeyWrapper.c_publicKey
            let c_u_privateKey = round0FinishedState.generatedKeyPairs.c_privateKey
            let sharedSecretWithV = try c_u_privateKey.sharedSecretFromKeyAgreement(with: c_v_publicKey)
            let symmectricKeyWithV = sharedSecretWithV.hkdfDerivedSymmetricKey(using: SA_HKDF_HashFunction.self,
                                                                               salt: round0FinishedState.config.salt,
                                                                               sharedInfo: Data(),
                                                                               outputByteCount: SASymmetricCipherKeyByteCount)
            // encrypt
            let dataToBeEncrypted = Model.SharesWrapper(u: ownUserId,
                                                        v: otherUserID,
                                                        s_uv_privateKeyShare: shares.s_uv_share,
                                                        b_uv_Share: shares.b_uv_share)
            let data = try JSONEncoder().encode(dataToBeEncrypted)
            let encryptedData = try SASymmetricCipher.seal(data, using: symmectricKeyWithV)
            return Model.EncryptedShare(e_uv: encryptedData,
                                        u: ownUserId,
                                        v: otherUserID)
        }
    }

    
    // MARK: Server -> Client
    /// Returns the information necessary for the server to send the Round1.ServerData
    func getRound1ServerRequestData() throws -> UserID {
        guard case .round1(let round1State) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        return round1State.ownUserID
    }
    
    func processRound1Data(_ serverMessage: Model.Round1.ServerData) throws {
        guard case .round1(let round1State) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        try state.advance(to: .round1Finished(Round1FinishedState(previousState: round1State, encryptedShares: serverMessage.encryptedServerMessagesForMe)))
    }
    
    // MARK: - Round 2
    // MARK: Client -> Server
    func round2() throws -> Model.Round2.ClientData<Value> {
        guard case .round1Finished(let currentState) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        let modulus = currentState.config.modulus
        // MARK: Assertions
        guard uniqueRemainingUsersOverThreshold(userIDs: currentState.U2, currentState: currentState) else {
            throw SecureAggregationError.protocolAborted(reason: .tThresholdUndercut)
        }
        // MARK: Compute p_uv
        // calculate shared secret with all remaining Users
        let maskWithOtherUsers = try currentState.otherUserPublicKeys.filter { otherUserPublicKeysWrapper in
            // Only remaining Users
            currentState.encryptedSharesForMe.contains { sharesWrapper in
                otherUserPublicKeysWrapper.userID == sharesWrapper.u
            }
        }.map { otherUserPublicKeysWrapper in
            (try currentState.generatedKeyPairs.s_privateKey.sharedSecretFromKeyAgreement(with: otherUserPublicKeysWrapper.s_publicKey), otherUserPublicKeysWrapper.userID)
        }.map { (sharedSecret, otherUserID) in
            // Expand shared secret s_uv into mask
            Value.mask(forSeed: sharedSecret, mod: modulus).cancelling(ownID: currentState.ownUserID, otherID: otherUserID, mod: currentState.config.modulus)
        }.reduce(Value.zero) { aggregate, value in
            aggregate.add(value, mod: modulus)
        }
        // Expand secret b_u into mask
        let b_u_sharedSecret = try currentState.b_u_privateKey.sharedSecretFromKeyAgreement(with: currentState.b_u_privateKey.publicKey)
        let ownMask = Value.mask(forSeed: b_u_sharedSecret, mod: modulus)
        // Add all masks to data
        let maskedValue = value
            .add(ownMask, mod: modulus)
            .add(maskWithOtherUsers, mod: modulus)
        try state.advance(to: .round2(Round2State<Value>(previousState: currentState)))
        return Model.Round2.ClientData(wrappedValue: Model.MaskedValueFromUser<Value>(maskedValue: maskedValue, origin: currentState.ownUserID))
    }
    
    // MARK: Server -> Client
    func processRound2Data(_ serverMessage: Model.Round2.ServerData) throws {
        guard case .round2(let round2State) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        try state.advance(to: .round2Finished(Round2FinishedState<Value>(previousState: round2State, remainingUsers: serverMessage.remainingUsers)))
    }
    
    // MARK: - Round4
    // MARK: Client -> Server
        
    func round4() throws -> Model.Round4.ClientData {
        guard case .round2Finished(let currentState) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        // MARK: Assertions
        // Verify U3 part of U4
        guard Set(currentState.U3).isSubset(of: currentState.U2) else {
            throw SecureAggregationError.protocolAborted(reason: .unexpecedUserInProtocol)
        }
        // Verify |U4| >= t
        guard uniqueRemainingUsersOverThreshold(userIDs: currentState.U3, currentState: currentState) else {
            throw SecureAggregationError.protocolAborted(reason: .tThresholdUndercut)
        }
        
        // MARK: Decrypt ciphertexts
        let decryptedShares = try currentState.encryptedSharesForMe.map { encryptedShare -> Model.SharesWrapper in
            // Key aggrement
            let optionalDecryptionKeys = currentState.otherUserPublicKeys.first { publicKeysOfUser in
                publicKeysOfUser.userID == encryptedShare.u
            }
            guard let decryptionPublicKey = optionalDecryptionKeys?.c_publicKey else {
                throw SecureAggregationError.protocolAborted(reason: .unexpecedUserInProtocol)
            }
            // decrypt
            let sharedSecret = try currentState.generatedKeyPairs.c_privateKey.sharedSecretFromKeyAgreement(with: decryptionPublicKey)
            let decryptionKey = sharedSecret.hkdfDerivedSymmetricKey(using: SA_HKDF_HashFunction.self, salt: currentState.config.salt, sharedInfo: Data(), outputByteCount: SASymmetricCipherKeyByteCount)
            let decryptedData = try SASymmetricCipher.open(encryptedShare.e_uv, using: decryptionKey)
            let decryptedWrapper = try JSONDecoder().decode(Model.SharesWrapper.self, from: decryptedData)
            // Assert
            guard decryptedWrapper.u == encryptedShare.u && decryptedWrapper.v == encryptedShare.v else {
                throw SecureAggregationError.protocolAborted(reason: .securityViolation(description: "Decrypted Shares wrong routing information"))
            }
            return decryptedWrapper
        }
        
        let result = decryptedShares.reduce(Model.Round4.ClientDataBuilder()) { aggregate, newValue in
            if currentState.U3.contains(newValue.u) {
                aggregate.add_b_uv(Model.AdressedShare(origin: newValue.u, destination: newValue.v, share: newValue.b_uv_Share))
            } else if (Set(currentState.U2).subtracting(currentState.U3)).contains(newValue.u) {
                aggregate.add_s_uv(Model.AdressedShare(origin: newValue.u, destination: newValue.v, share: newValue.s_uv_privateKeyShare))
            }
            return aggregate
        }.finish()
        // TODO: add (own) b_uu to server message
        
        try state.advance(to: .round4(Round4State<Value>(previousState: currentState)))
        
        return result
    }

    // MARK: Server -> Client
    func processRound4Data(_ serverMessage: Model.Round4.ServerData<Value>) throws {
        guard case .round4(_) = state else {
            throw SecureAggregationError.incorrectStateForMethod
        }
        try state.advance(to: .finished(serverMessage.value))
    }
}
