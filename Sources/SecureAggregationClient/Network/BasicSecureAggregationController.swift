//
//  File.swift
//  
//
//  Created by stephan on 17.08.21.
//

import Foundation
import Combine
import SecureAggregationCore
import SwiftUI
import Logging
import Vapor

public class BasicSecureAggregationController<Value: SAWrappedValue>: ObservableObject, Identifiable {
    /// For Views only
    public let id = UUID()
    
    @Published private var model: SecureAggregationModel<Value>
    
    public var status: SecureAggregationStatus<Value> {
        SecureAggregationStatus<Value>(model.state)
    }
    
    public var requestInProgress: Bool {
        server.currentRequest != nil
    }
    
    public var value: Value {
        model.value
    }
    
    private var modelWillChangeCancellable: AnyCancellable?
    
    private let server: ServerRequestHandler
    
    public init(value: Value, serverBaseURL: URL) {
        self.model = SecureAggregationModel(value: value)
        server = ServerRequestHandler(serverBaseURL: serverBaseURL)
        
        // From https://stackoverflow.com/a/58406402 :
        modelWillChangeCancellable = model.objectWillChange.sink { [weak self] (_) in
            self?.objectWillChange.send()
        }
    }
    
    public var description: String {
        "value: \(value.description), status: \(status.description)"
    }
        
    public func start() {
        server.requestIgnoringResponse(for: .start)
    }
    
    public func login() {
        server.request(for: .login, decodeInto: UserID.self) { userID in
            try self.model.saveLoginData(userID: userID)
            return ()
        }
    }
    
    public func finishLogin() {
        server.requestIgnoringResponse(for: .finishLogin)
    }
    
    public func setup() {
        server.request(for: .setup,
                            decodeInto: SAConfiguration.self,
                            callToModel: model.saveSetupData)
    }
    
    public func finishSetup() {
        server.requestIgnoringResponse(for: .finishSetup)
    }
    
    public func round0SendMessage() {
        server.requestIgnoringReponse(for: .round0ClientMessage) {
            Network.Round0.ClientData(try self.model.round0())
        }
    }
    
    public func finishRound0Collection() {
        server.requestIgnoringResponse(for: .finishRound0Collection)
    }
    
    public func round0DownloadServerMessage() {
        server.request(for: .round0ServerMessage,
                            decodeInto: Network.Round0.ServerData.self) { data in
            try self.model.processRound0Data(try data.unwrap())
        }
    }
    
    public func advanceToRound1() {
        server.requestIgnoringResponse(for: .advanceToRound1)
    }
    
    public func round1SendMessage() {
        server.requestIgnoringReponse(for: .round1ClientMessage) {
            try Network.Round1.ClientData(try self.model.round1())
        }
    }
    
    public func finishRound1Collection() {
        server.requestIgnoringResponse(for: .finishRound1Collection)
    }
    
    public func round1DownloadServerMessage() {
        guard let userID = try? model.getRound1ServerRequestData(),
              let userIDData = try? JSONEncoder().encode(userID) else {
            logger.network(endpoint: .round1ServerMessage, "Could not load userID from Model")
            return
        }
        server.request(for: .round0ServerMessage,
                       body: userIDData,
                       decodeInto: Network.Round1.ServerData.self) { result in
            try self.model.processRound1Data(try result.unwrap())
        }
    }

    public func advanceToRound2() {
        server.requestIgnoringResponse(for: .advanceToRound2)
    }

    public func round2SendMessage() {
        server.requestIgnoringReponse(for: .round2ClientMessage) {
            Network.Round2.ClientData(try self.model.round2())
        }
    }
    
    public func finishRound2Collection() {
        server.requestIgnoringResponse(for: .finishRound2Collection)
    }
    
    public func round2DownloadServerMessage() {
        server.request(for: .round2ServerMessage,
                            decodeInto: Network.Round2.ServerData.self) { data in
            try self.model.processRound2Data(data.unwrap())
        }
    }

    public func advanceToRound4() {
        server.requestIgnoringResponse(for: .advanceToRound4)
    }

    public func round4SendMessage() {
        server.requestIgnoringReponse(for: .round4ClientMessage) {
            Network.Round4.ClientData<SAInt>(try self.model.round4())
        }
    }
    
    public func finishRound4Collection() {
        server.requestIgnoringResponse(for: .finishRound4Collection)
    }
    
    public func round4DownloadServerMessage() {
        server.request(for: .round4ServerMessage,
                            decodeInto: Network.Round4.ServerData.self) { data in
            try self.model.processRound4Data(data.unwrap())
        }
    }
}

