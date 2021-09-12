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

class BasicSecureAggregationController<Value: SAWrappedValue>: ObservableObject {
    @Published var model: SecureAggregationModel<Value>
    
    private var modelWillChangeCancellable: AnyCancellable? = nil
    
    init(value: Value) {
        self.model = SecureAggregationModel(value: value)
        // From https://stackoverflow.com/a/58406402 :
        modelWillChangeCancellable = model.objectWillChange.sink { [weak self] (_) in
            self?.objectWillChange.send()
        }
    }
    
    
}

