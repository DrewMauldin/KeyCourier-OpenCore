import XCTest
@testable import KeyCourierCore

final class GuidedDestinationTests: XCTestCase {
    func testBuiltInDestinationsHaveStableFriendlyMappings() throws {
        XCTAssertEqual(
            GuidedDestination.allCases,
            [.thisMac, .macMini, .vps, .cloudMemoryProjection]
        )

        XCTAssertEqual(GuidedDestination.thisMac.displayName, "This Mac")
        XCTAssertEqual(GuidedDestination.thisMac.secretIDValue, "this-mac-secret")
        XCTAssertEqual(GuidedDestination.thisMac.consumerIDValue, "this-mac")
        XCTAssertEqual(GuidedDestination.thisMac.targetIDValue, "this-mac")

        XCTAssertEqual(GuidedDestination.macMini.displayName, "Mac Mini")
        XCTAssertEqual(GuidedDestination.macMini.secretIDValue, "mac-mini-secret")
        XCTAssertEqual(GuidedDestination.macMini.consumerIDValue, "mac-mini")
        XCTAssertEqual(GuidedDestination.macMini.targetIDValue, "mac-mini")

        XCTAssertEqual(GuidedDestination.vps.displayName, "VPS")
        XCTAssertEqual(GuidedDestination.vps.secretIDValue, "vps-secret")
        XCTAssertEqual(GuidedDestination.vps.consumerIDValue, "vps")
        XCTAssertEqual(GuidedDestination.vps.targetIDValue, "vps")

        XCTAssertEqual(
            GuidedDestination.cloudMemoryProjection.displayName,
            "Cloud Memory Projection Executor"
        )
        XCTAssertEqual(
            GuidedDestination.cloudMemoryProjection.secretIDValue,
            "cloud-memory-projection-secret"
        )
        XCTAssertEqual(
            GuidedDestination.cloudMemoryProjection.consumerIDValue,
            "cloud-memory-projection"
        )
        XCTAssertEqual(GuidedDestination.cloudMemoryProjection.targetIDValue, "vps")
    }

    func testRemoteBuiltInConsumerProfilesRemainRemoteAndFailClosed() throws {
        XCTAssertEqual(GuidedDestination.remoteCases, [.macMini, .vps])

        for destination in GuidedDestination.remoteCases {
            let profile = try destination.consumerProfile()
            XCTAssertEqual(profile.id.rawValue, destination.consumerIDValue)
            XCTAssertEqual(profile.targetID.rawValue, destination.targetIDValue)
            XCTAssertEqual(profile.destination, .remoteAge(profile: destination.consumerIDValue))
        }

        let projection = try GuidedDestination.cloudMemoryProjection.consumerProfile()
        XCTAssertEqual(projection.id.rawValue, "cloud-memory-projection")
        XCTAssertEqual(projection.targetID.rawValue, "vps")
        XCTAssertEqual(projection.destination, .remoteAge(profile: "cloud-memory-projection"))
    }

    func testThisMacConsumerUsesOnlyTheManagedLocalInstallation() throws {
        let directories = AppDirectories(root: URL(fileURLWithPath: "/private/tmp/KeyCourierTests"))
        let profile = try GuidedDestination.thisMac.consumerProfile(directories: directories)

        XCTAssertEqual(profile.id.rawValue, "this-mac")
        XCTAssertEqual(profile.targetID.rawValue, "this-mac")
        XCTAssertEqual(
            profile.destination,
            .dotenv(
                path: "/private/tmp/KeyCourierTests/Installations/this-mac.env",
                variable: "KEYCOURIER_SECRET"
            )
        )
    }

    func testFriendlyLookupRequiresTheCompleteBuiltInMapping() throws {
        let destination = GuidedDestination.macMini
        XCTAssertEqual(
            GuidedDestination.matching(
                secretID: try SecretID(validating: destination.secretIDValue),
                consumerID: try ConsumerID(validating: destination.consumerIDValue),
                targetID: try TargetID(validating: destination.targetIDValue)
            ),
            .macMini
        )
        XCTAssertNil(
            GuidedDestination.matching(
                secretID: try SecretID(validating: destination.secretIDValue),
                consumerID: try ConsumerID(validating: "different-consumer"),
                targetID: try TargetID(validating: destination.targetIDValue)
            )
        )
    }
}
