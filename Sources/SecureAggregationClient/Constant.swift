//
//  File.swift
//  
//
//  Created by stephan on 15.07.21.
//

import Foundation

struct Const {
    // MARK: - Networking
    static let urlSessionInstance = URLSession.shared
    static let serverBaseURL = URL(string: "TODO") // TODO
    static let secureAggregationBaseURL = URL(string: "TODO", relativeTo: serverBaseURL)
}
