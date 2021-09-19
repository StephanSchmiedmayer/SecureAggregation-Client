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

    // MARK: - API
    // So many different functions and not one with optionals because optionals would be from Generic type, and from nil no Type can be inferred => :(
    
    /// Sends a request to the server, ignoring any successful response from the server. Logs any error
    ///
    /// `modelAccess` gets called to load the body of the request
    func requestIgnoringReponse<BodyType: SANetworkMessage>(for endpoint: SABasicAPI,
                                                            modelToNetwork: @escaping () throws -> BodyType) {
        do {
            request(try createRequest(for: endpoint, withBody: try modelToNetwork()),
                    task: ignoreServerResponse(fromEndpoint: endpoint))
        } catch {
            logger.network(endpoint: endpoint, "Failed send request: \(error)")
        }
    }
        
    /// Makes a request to the server disregarding the response, logging any error
    func requestIgnoringResponse(for endpoint: SABasicAPI) {
        request(createRequest(for: endpoint), task: ignoreServerResponse(fromEndpoint: endpoint))
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
                                         decodeInto decoderType: DecoderType.Type,
                                         callToModel: @escaping (DecoderType) throws -> Void) {
        request(createRequest(for: endpoint), task: decodeAndCallToModel(endpoint: endpoint,
                                                                         decodeInto: decoderType,
                                                                         callToModel: callToModel))
    }
        
    func request<DecoderType: Decodable, BodyType: SANetworkMessage>(
        for endpoint: SABasicAPI,
        decodeInto decoderType: DecoderType.Type,
        body: BodyType,
        callToModel: @escaping (DecoderType) throws -> Void) {
        do {
            request(try createRequest(for: endpoint, withBody: body),
                    task: decodeAndCallToModel(endpoint: endpoint,
                                               decodeInto: decoderType,
                                               callToModel: callToModel))
        } catch {
            logger.network(endpoint: endpoint, "Failed send request: \(error)")
        }
    }
    
    // MARK: - private Helper
    
    // MARK: Standard server response handler
    
    /// Function returning a function usable to ignore the server response as `task` in `request(_:task:)`
    private func ignoreServerResponse(fromEndpoint endpoint: SABasicAPI) ->
    ((AnyPublisher<Data, Publishers.TryMap<URLSession.DataTaskPublisher, Data>.Failure>) -> AnyPublisher<Void, Never>) {
        { result in
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
    
    private func decodeAndCallToModel<DecoderType: Decodable>(endpoint: SABasicAPI,
                                                              decodeInto decoderType: DecoderType.Type,
                                                              callToModel: @escaping (DecoderType) throws -> Void) ->
    ((AnyPublisher<Data, Publishers.TryMap<URLSession.DataTaskPublisher, Data>.Failure>) -> AnyPublisher<Void, Never>) {
        { result in
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

    // MARK: Create request
    
    /// Creates an URLRequest to the endpoint with the given body
    private func createRequest<BodyType: Encodable>(for endpoint: SABasicAPI, withBody body: BodyType) throws -> URLRequest {
        guard let bodyData = try? JSONEncoder().encode(body) else {
            logger.network(endpoint: endpoint, "Failed to JSON-encode \(BodyType.Type.self)")
            throw SecureAggregationNetworkError.encodingError
        }
        var result = createRequest(for: endpoint)
        result.httpBody = bodyData
        result.addValue("application/json", forHTTPHeaderField: "content-type")
        return result
    }
        
    private func createRequest(for endpoint: SABasicAPI) -> URLRequest {
        var result = URLRequest(url: serverBaseURL.appendingPathComponent(endpoint.info.fullRelativeURL))
        result.httpMethod = endpoint.info.method.rawValue
        return result
    }
    
    // MARK: Make actual request
    
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
