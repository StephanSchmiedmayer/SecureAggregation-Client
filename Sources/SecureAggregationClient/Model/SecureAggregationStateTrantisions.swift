//
//  File.swift
//  
//
//  Created by stephan on 17.08.21.
// This is a copy of secureaggregationserver SecureAggregationStateTransitions

import Foundation
import SecureAggregationCore

// Implementation of the State machine. Maybe better with github statemachine?
extension SecureAggregationRoundState {
    mutating func advance(to targetState: SecureAggregationRoundState) throws {
        guard validTransition(from: self, to: targetState) else {
            throw SecureAggregationError.invalidStateTransition
        }
        self = targetState
    }
    
    private func validTransition(from originalState: SecureAggregationRoundState, to targetState: SecureAggregationRoundState) -> Bool {
        switch originalState {
        case .waiting:
            if case .login = targetState { return true }
        case .login(_):
            if case .setup = targetState { return true }
        case .setup:
            if case .round0 = targetState { return true }
        case .round0:
            if case .round0Finished = targetState { return true }
        case .round0Finished(_):
            if case .round1 = targetState { return true }
        case .round1:
            if case .round1Finished = targetState { return true }
        case .round1Finished(_):
            if case .round2 = targetState { return true }
        case .round2:
            if case .round2Finished = targetState { return true }
        case .round2Finished(_):
            if case .round4 = targetState { return true }
        case .round4:
            if case .finished = targetState { return true }
        case .aborted, .finished(_):
            break
        }
        return false
    }
    
    /// Aborts the protocol
    mutating func abort(becauseOf reason: SecureAggregationProtocolError) {
        self = .aborted(reason: reason)
    }
}
