import KeyCourierCore

extension AppModel {
    var destinationSummaries: [DestinationSummary] {
        GuidedDestination.allCases.map { destination in
            let matchingConsumer = consumers.first { $0.id.rawValue == destination.consumerIDValue }
            let expectedConsumer = try? destination.consumerProfile(directories: directories)
            let registration: DestinationRegistration
            if matchingConsumer == expectedConsumer {
                registration = .registered
            } else if matchingConsumer == nil {
                registration = .missing
            } else {
                registration = .conflict
            }
            return DestinationSummary(
                destination: destination,
                registration: registration
            )
        }
    }

    func requestTitle(_ request: SecretRequest) -> String {
        if let destination = GuidedDestination.matching(
            secretID: request.secretID,
            consumerID: request.consumerID,
            targetID: request.targetID
        ) {
            return destination.displayName
        }
        return consumers.first { $0.id == request.consumerID }?.displayName ?? "Unknown destination"
    }

    func requestCredentialName(_ request: SecretRequest) -> String {
        secrets.first { $0.id == request.secretID }?.displayName
            ?? request.secretID.rawValue
    }

    func receiptDestinationName(_ receipt: RequestReceipt) -> String {
        if let destination = GuidedDestination.matching(
            consumerID: receipt.consumerID,
            targetID: receipt.targetID
        ) {
            return destination.displayName
        }
        return consumers.first { $0.id == receipt.consumerID }?.displayName ?? "Custom destination"
    }

    func isBuiltIn(_ secret: SecretMetadata) -> Bool {
        GuidedDestination.allCases.contains { $0.secretIDValue == secret.id.rawValue }
    }

    func isBuiltIn(_ consumer: ConsumerProfile) -> Bool {
        GuidedDestination.allCases.contains { $0.consumerIDValue == consumer.id.rawValue }
    }
}
