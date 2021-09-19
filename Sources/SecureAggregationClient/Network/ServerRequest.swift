//
//  File.swift
//  
//
//  Created by stephan on 14.09.21.
//

import Foundation
import Combine
import SecureAggregationCore
import Vapor

class ServerRequestHandler {
    /// The base URL of the server
    let serverBaseURL: URL
    
    private let urlsession: URLSession
    
    /// Last request made to the server
    ///
    /// There is at most always only 1 request that can still be executed.
    private(set) var currentRequest: AnyCancellable?
    
    init(serverBaseURL: URL) {
        self.serverBaseURL = serverBaseURL
        self.urlsession = URLSession(configuration: .default)
    }
    
//    func requestIgnoringResponse<BodyType: Encodable>(for endpoint: SABasicAPI, body: BodyType) {
//        guard let encodedBody = try? JSONEncoder().encode(body) else {
//            logger.network(endpoint: endpoint, "Failed to encode data for server Request")
//            return
//        }
//        requestIgnoringResponse(for: endpoint, body: encodedBody)
//    }
    
    /// Sends a request to the server, ignoring any successful response from the server. Logs any error
    ///
    /// modelAccess gets called to load the body of the request
    ///
    func requestIgnoringReponse<BodyType: Encodable>(for endpoint: SABasicAPI,
                                                     modelToNetwork: @escaping () throws -> BodyType) {
        do {
            let encodedBody = try JSONEncoder().encode(try modelToNetwork())
            requestIgnoringResponse(for: endpoint, body: encodedBody)
        } catch {
            logger.network(endpoint: endpoint, "Failed to access model / encode data for server Request: \(error)")
        }
    }
        
    /// Makes a request to the server disregarding the response, logging any error
    func requestIgnoringResponse(for endpoint: SABasicAPI, body: Data? = nil) {
        request(for: endpoint, withBody: body) { result in
            result
                .map { _ in
                    ()
                }
                .catch { error -> Just<Void> in
                    logger.network(endpoint: endpoint, "requestWithoutResponse: Caught unexpected error: \(error)")
                    return Just<Void>(())
                }
                .eraseToAnyPublisher()
        }
    }
    
    /// Sends an empty request to the given endpoint.
    ///
    /// Catches and logs any error
    ///
    /// - Parameters:
    ///     - endpoint: The endpoint to send the request to
    ///     - decodeInto: Type to decode the server response into
    ///     - callToMethod: Closure executed with the decoded result from the server. Guaranteed to be called from the main Queue
    func request<DecoderType: Decodable>(for endpoint: SABasicAPI,
                                         body: Data? = nil,
                                         decodeInto decoderType: DecoderType.Type,
                                         callToModel: @escaping (DecoderType) throws -> Void) {
        request(for: endpoint, withBody: body) { result in
            result
                .decode(type: DecoderType.self, decoder: JSONDecoder())
                .receive(on: DispatchQueue.main)
                .tryMap { result in
                    try callToModel(result)
                }
                .catch { error -> Just<Void> in
                    logger.network(endpoint: endpoint, "requestAndCallModel: Caught unexpected error: \(error)")
                    return Just<Void>(())
                }
                .eraseToAnyPublisher()
        }
    }
        
    private func createRequest(for endpoint: SABasicAPI, withBody body: Data? = nil) -> URLRequest {
        var result = URLRequest(url: serverBaseURL.appendingPathComponent(endpoint.info.fullRelativeURL))
        result.httpMethod = endpoint.info.method.rawValue
        result.httpBody = body
        return result
    }
    
    private func request(for endpoint: SABasicAPI,
                         withBody body: Data? = nil,
                         task: @escaping (AnyPublisher<Data, Publishers.TryMap<URLSession.DataTaskPublisher, Data>.Failure>) -> AnyPublisher<Void, Never>) {
        request(createRequest(for: endpoint, withBody: body), task: task)
    }
    
    /// Makes a new Request to the server.
    private func request(_ request: URLRequest, task: @escaping (AnyPublisher<Data, Publishers.TryMap<URLSession.DataTaskPublisher, Data>.Failure>) -> AnyPublisher<Void, Never>) {
        currentRequest?.cancel()
        let dataPublisher = urlsession
            .dataTaskPublisher(for: request)
            .tryMap { element -> Data in
                guard let httpResponse = element.response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    throw URLError(.badServerResponse)
                }
                return element.data
            }
            .eraseToAnyPublisher()
        currentRequest = task(dataPublisher)
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    self.currentRequest = nil
                    // TODO: log
                }
            }, receiveValue: { _ in
                // TODO log
            })
    }
}
