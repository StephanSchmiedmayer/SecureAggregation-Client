//
//  File.swift
//  
//
//  Created by stephan on 29.08.21.
//

import Foundation
import SwiftySSS

extension Array {
    /// Checks if all elements in self pointed to by the keyPath are unique
    ///
    ///
    func allUnique<T: Equatable & Hashable>(_ keyPath: KeyPath<ArrayLiteralElement, T>) -> Bool {
        return Set(self.map { $0[keyPath: keyPath] }).count == self.count // TODO: hash-collisions?
    }
    
    /// Appends the given Element and returns a modified copy of self. Does not modify `self`
    func appended(_ element: Element) -> Self {
        var copy = self
        copy.append(element)
        return copy
    }
}
