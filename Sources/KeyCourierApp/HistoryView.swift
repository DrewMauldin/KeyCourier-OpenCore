import KeyCourierCore
import SwiftUI

struct HistoryView: View {
    let model: AppModel

    var body: some View {
        Group {
            if model.receipts.isEmpty {
                ContentUnavailableView(
                    "No history yet",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Completed and declined requests will appear here without any secret values.")
                )
            } else {
                List(model.receipts) { receipt in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: image(for: receipt.status))
                            .foregroundStyle(colour(for: receipt.status))
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(statusText(for: receipt.status))
                                .font(.headline)
                            Text(model.receiptDestinationName(receipt))
                            Text(detailText(for: receipt.code))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Text(receipt.recordedAt.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 5)
                    .accessibilityElement(children: .combine)
                }
            }
        }
        .navigationTitle("Activity")
    }

    private func statusText(for status: ReceiptStatus) -> String {
        switch status {
        case .verified: "Delivered"
        case .failed: "Could not deliver"
        case .offline: "Destination offline"
        case .denied: "Declined"
        case .notConfigured: "Setup needed"
        }
    }

    private func detailText(for code: ReceiptCode) -> String {
        switch code {
        case .consumerVerified: "The destination confirmed the install."
        case .ownerDenied: "You declined this request."
        case .secretMissing: "No saved secret was found."
        case .secretExpired: "This credential has expired. Replace it before trying again."
        case .consumerMissing: "The destination is not registered."
        case .targetUnavailable: "Secure delivery is not set up yet."
        case .validationFailed: "The request did not pass the safety checks."
        case .deliveryFailed: "The destination could not complete the install."
        }
    }

    private func image(for status: ReceiptStatus) -> String {
        switch status {
        case .verified: "checkmark.seal.fill"
        case .failed, .offline: "exclamationmark.triangle.fill"
        case .denied: "xmark.circle.fill"
        case .notConfigured: "wrench.and.screwdriver.fill"
        }
    }

    private func colour(for status: ReceiptStatus) -> Color {
        switch status {
        case .verified: .green
        case .failed, .offline, .notConfigured: .orange
        case .denied: .secondary
        }
    }
}
