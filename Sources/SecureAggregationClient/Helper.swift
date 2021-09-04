//
//  File.swift
//  
//
//  Created by stephan on 29.08.21.
//

import Foundation
import ShamirSecretShare

extension Array {
    /// Checks if all elements in self pointed to by the keyPath are unique
    ///
    ///
    func allUnique<T: Equatable & Hashable>(_ keyPath: KeyPath<ArrayLiteralElement, T>) -> Bool {
        return Set(self.map { $0[keyPath: keyPath] }).count == self.count // TODO: hash-collisions?
    }
}
