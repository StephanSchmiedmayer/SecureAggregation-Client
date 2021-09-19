//
//  File.swift
//  
//
//  Created by stephan on 17.09.21.
//

import Foundation
import Logging
import SecureAggregationCore

let logger = SALogger()

struct SALogger {
    private let _logger: Logger
    
    fileprivate init() {
        self._logger = Logger(label: "de.tum.secureAggregation")
        _logger.info("SecureAggregationClient Logger initialization")
    }
        
    func network(endpoint: SABasicAPI, errorCaught error: Error) {
        network(endpoint: endpoint, "Caught error \(error)")
    }
    
    func network(endpoint: SABasicAPI, _ message: Logger.Message) {
        _logger.info("Network: \(endpoint.rawValue): \(message)")
    }
}
