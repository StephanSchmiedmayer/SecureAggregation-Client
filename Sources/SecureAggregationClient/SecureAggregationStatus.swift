//
//  SecureAggregationStatus.swift
//  SecureAggregationClient
//
//  Created by stephan on 12.09.21.
//

import Foundation
import SecureAggregationCore

/// Simplification of SecureAggregationRoundState
enum SecureAggregationStatus<Value: SAWrappedValue> {
    case aborted(reason: SecureAggregationProtocolError)
    case waiting
    case login
    case setup
    case round0
    case round0Finished
    case round1
    case round1Finished
    case round2
    case round2Finished
    case round4
    case finished(_: Value)

    
    init(_ roundState: SecureAggregationRoundState<Value>) {
        switch roundState {
        case .aborted(reason: let reason):
            self = .aborted(reason: reason)
        case .waiting:
            self = .waiting
        case .login(_):
            self = .login
        case .setup(_):
            self = .setup
        case .round0(_):
            self = .round0
        case .round0Finished(_):
            self = .round0Finished
        case .round1(_):
            self = .round1
        case .round1Finished(_):
            self = .round1Finished
        case .round2(_):
            self = .round2
        case .round2Finished(_):
            self = .round2Finished
        case .round4(_):
            self = .round4
        case .finished(let value):
            self = .finished(value)
        }
    }
}
