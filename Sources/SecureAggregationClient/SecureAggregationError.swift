//
//  File.swift
//  
//
//  Created by stephan on 28.08.21.
//

import Foundation

enum SecureAggregationProtocolError {
    case tThresholdUndercut
    case unexpecedUserInProtocol
    case securityViolation(description: String?)
}

enum SecureAggregationError: Error {
    case incorrectStateForMethod
    case invalidStateTransition
    case protocolAborted(reason: SecureAggregationProtocolError)
}
