import SwiftUI

struct MobileRequestsView: View {
    let model: CompanionAppModel

    var body: some View {
        NavigationStack {
            List {
                ApprovalSummaryCard(requestCount: model.requests.count)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16))
                    .listRowSeparator(.hidden)

                if model.requests.isEmpty {
                    ContentUnavailableView(
                        "No approvals waiting",
                        systemImage: "checkmark.circle.fill",
                        description: Text("You are all caught up. New requests will appear here with their credential and destination.")
                    )
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                } else {
                    Section("Waiting for you") {
                        ForEach(model.requests) { request in
                            MobileRequestRow(model: model, request: request)
                                .listRowBackground(Color.clear)
                                .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
                                .listRowSeparator(.hidden)
                        }
                    }
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background { MobileBackdrop() }
            .refreshable { await model.refresh() }
            .navigationTitle("Approvals")
            .toolbar {
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await model.refresh() }
                }
            }
        }
    }
}

private struct ApprovalSummaryCard: View {
    let requestCount: Int

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: requestCount == 0 ? "checkmark.shield.fill" : "bell.badge.fill")
                .font(.system(size: 30, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(requestCount == 0 ? Color.green : Color.accentColor)
                .frame(width: 52, height: 52)
                .background(.thinMaterial, in: .rect(cornerRadius: 15))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(requestCount == 0 ? "Everything is protected" : "\(requestCount) waiting for you")
                    .font(.title2.bold())
                Text("Review the credential, destination and reason. Face ID confirms every decision.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(20)
        .mobileSurface()
        .accessibilityElement(children: .combine)
    }
}

private struct MobileRequestRow: View {
    let model: CompanionAppModel
    let request: CompanionRequestSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(request.destinationName)
                    .font(.headline)
                Spacer()
                Text(request.clientName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Label(request.credentialName, systemImage: "key.fill")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.tint)
            Text(request.reason)
                .fixedSize(horizontal: false, vertical: true)
            LabeledContent("Expires") {
                Text(request.expiresAt, format: .dateTime.hour().minute())
            }
            HStack {
                Button("Decline", role: .destructive) {
                    Task { await model.decide(.deny, request: request) }
                }
                .frame(maxWidth: .infinity)
                Button("Approve") {
                    Task { await model.decide(.approve, request: request) }
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
            }
            .disabled(model.isWorking)
        }
        .padding(16)
        .mobileSurface(cornerRadius: 18)
        .accessibilityElement(children: .contain)
    }
}
