//
//  ReducedSAStatus.swift
//  shoppingList
//
//  Created by stephan on 19.09.21.
//

import Foundation
import SecureAggregationCore
/*
/// Reduced SAStatus, Rawvalue represents the number of the status. Increases from 0 (`waiting`) in order of the protocol, aborted is -1
///
/// - Important:
///     Do not rely on the raw value being associated with a specific value (because of changes to this API).
///     Use only to compare the order of two states or determine if two states are equal except associated values.
public enum ReducedSAStatus: Int, Hashable, CaseIterable {
    case aborted = -1
    case waiting = 0
    case login
    case setup
    case round0
    case round0Finished
    case round1
    case round1Finished
    case round2
    case round2Finished
    case round4
    case finished
    
    init<Value: SAWrappedValue>(_ sastatus: SecureAggregationStatus<Value>) {
        switch sastatus {
        case .aborted(_):
            self = .aborted
        case .waiting:
            self = .waiting
        case .login:
            self = .login
        case .setup:
            self = .setup
        case .round0:
            self = .round0
        case .round0Finished:
            self = .round0Finished
        case .round1:
            self = .round1
        case .round1Finished:
            self = .round1Finished
        case .round2:
            self = .round2
        case .round2Finished:
            self = .round2Finished
        case .round4:
            self = .round4
        case .finished(_):
            self = .finished
        }
    }
}

extension ReducedSAStatus: CustomStringConvertible {
    public var description: String {
        switch self {
        case .aborted:
            return "aborted"
        case .waiting:
            return "waiting"
        case .login:
            return "login"
        case .setup:
            return "setup"
        case .round0:
            return "round0"
        case .round0Finished:
            return "round0Finished"
        case .round1:
            return "round1"
        case .round1Finished:
            return "round1Finished"
        case .round2:
            return "round2"
        case .round2Finished:
            return "round2Finished"
        case .round4:
            return "round4"
        case .finished:
            return "finished"
        }
    }
}

extension ReducedSAStatus: Comparable {
    public static func < (lhs: ReducedSAStatus, rhs: ReducedSAStatus) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
*/
