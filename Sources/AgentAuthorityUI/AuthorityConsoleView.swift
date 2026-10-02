#if canImport(SwiftUI)
import SwiftUI
import AgentAuthority

/// The console: three agents, the grants they hold, a long-running agent task
/// you can revoke mid-flight, the adversarial suite, and the audit chain.
public struct AuthorityConsoleView: View {
    @Bindable private var model: AuthorityConsoleModel

    public init(model: AuthorityConsoleModel) {
        self.model = model
    }

    public var body: some View {
        NavigationStack {
            List {
                headerSection
                agentsSection
                jobSection
                suiteSection
                auditSection
                activitySection
            }
            .navigationTitle("Agent Authority")
            .task { await model.refreshAudit() }
            .sheet(item: $model.consentSheetItem) { pending in
                ConsentSheet(challenge: pending.challenge) { approved in
                    model.resolveConsent(approved: approved)
                }
                .interactiveDismissDisabled()
            }
        }
    }

    // MARK: Sections

    private var headerSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                Text("Every agent call is exchanged for a short-lived, scope-bound, key-bound token.")
                    .font(.subheadline)
                Label(model.hardwareBackedKeys ? "Proof keys: Secure Enclave" : "Proof keys: software P-256 (no Secure Enclave here)",
                      systemImage: model.hardwareBackedKeys ? "lock.shield.fill" : "key")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Revocation generation: \(model.generation)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var agentsSection: some View {
        Section("Agents") {
            ForEach(model.agents) { agent in
                AgentRow(agent: agent, model: model)
            }
            Button(role: .destructive) {
                Task { await model.revokeAll() }
            } label: {
                Label("Kill switch: revoke every token", systemImage: "bolt.slash.fill")
            }
        }
    }

    private var jobSection: some View {
        Section("In-flight task") {
            Text("The on-device model re-authorizes before every step. Revoke it while the task runs and it stops at the next step.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button("Start 8-step task") {
                    model.startJob(as: Ledger.budgetModel)
                }
                .disabled(isJobRunning)
                Spacer()
                Button("Revoke model", role: .destructive) {
                    Task { await model.revoke(Ledger.budgetModel) }
                }
            }
            .buttonStyle(.borderless)
            jobStatus
        }
    }

    private var isJobRunning: Bool {
        if case .running = model.job { return true }
        return false
    }

    @ViewBuilder private var jobStatus: some View {
        switch model.job {
        case .idle:
            Text("Idle — grant the model “transactions.read” first.").font(.caption)
        case .running(let step, let total):
            ProgressView(value: Double(step), total: Double(max(total, 1))) {
                Text("Step \(step) of \(total)").font(.caption)
            }
        case .finished(let steps):
            Label("Finished all \(steps) steps", systemImage: "checkmark.circle").foregroundStyle(.green)
        case .stopped(let step, let reason):
            Label("Stopped at step \(step): \(reason)", systemImage: "xmark.octagon").foregroundStyle(.red).font(.caption)
        }
    }

    private var suiteSection: some View {
        Section {
            Button {
                Task { await model.runSuite() }
            } label: {
                Label(model.isRunningSuite ? "Running…" : "Run adversarial suite", systemImage: "shield.lefthalf.filled")
            }
            .disabled(model.isRunningSuite)
            ForEach(model.suiteResults) { result in
                ScenarioRow(result: result)
            }
        } header: {
            Text("Adversarial suite")
        } footer: {
            if !model.suiteResults.isEmpty {
                let attacks = model.suiteResults.filter { $0.expectedDenial != nil }.count
                Text("\(model.suitePassCount) of \(model.suiteResults.count) scenarios behaved as expected (\(attacks) attacks that must be stopped for a specific reason, \(model.suiteResults.count - attacks) baselines that must be allowed).")
            }
        }
    }

    private var auditSection: some View {
        Section("Audit chain") {
            HStack {
                auditBadge(model.auditStatus, intactText: "Chain intact", nilText: "Not verified yet")
                Spacer()
                Button("Tamper with a copy") {
                    Task { await model.demonstrateTamper() }
                }
                .buttonStyle(.borderless)
            }
            if model.tamperStatus != nil {
                auditBadge(model.tamperStatus, intactText: "Tamper NOT detected", nilText: "")
            }
            ForEach(model.auditEntries.suffix(12).reversed()) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    Text("#\(entry.sequence) \(entry.event.kind.rawValue) · \(entry.event.agentID)")
                        .font(.caption.monospaced())
                    Text(entry.event.detail)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
        }
    }

    @ViewBuilder
    private func auditBadge(_ verdict: AuditVerification?, intactText: String, nilText: String) -> some View {
        switch verdict {
        case .intact(let count)?:
            Label("\(intactText) (\(count) entries)", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
        case .broken(let index)?:
            Label("Chain broken at entry \(index)", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
        case nil:
            Text(nilText).foregroundStyle(.secondary)
        }
    }

    private var activitySection: some View {
        Section("Activity") {
            if model.activity.isEmpty {
                Text("No agent activity yet.").foregroundStyle(.secondary)
            }
            ForEach(model.activity.suffix(15).reversed()) { line in
                HStack(alignment: .top) {
                    Image(systemName: line.allowed ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(line.allowed ? .green : .red)
                    VStack(alignment: .leading) {
                        Text(line.agentID).font(.caption.bold())
                        Text(line.text).font(.caption)
                    }
                }
            }
        }
    }
}

private struct AgentRow: View {
    let agent: AgentPrincipal
    let model: AuthorityConsoleModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(agent.displayName).font(.headline)
                Spacer()
                Text(agent.kind.rawValue).font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            if let credential = model.credential(for: agent.id) {
                Text(credential.token.scopes.sorted().map(\.name).joined(separator: " · "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .strikethrough(model.isRevoked(agent.id))
                if model.isRevoked(agent.id) {
                    Text("Revoked — the agent still holds this token; the broker refuses it")
                        .font(.caption2)
                        .foregroundStyle(.red)
                }
            } else {
                Text("No token").font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Button("Grant read") {
                    Task { await model.request([Ledger.readTransactions], for: agent) }
                }
                Button("Grant pay") {
                    Task { await model.request([Ledger.initiatePayment], for: agent) }
                }
                Button("Pay") {
                    Task { await model.invoke(Ledger.pay, as: agent) }
                }
                Button("Revoke", role: .destructive) {
                    Task { await model.revoke(agent) }
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .font(.caption)
        }
        .padding(.vertical, 4)
    }
}

private struct ScenarioRow: View {
    let result: ScenarioResult

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: result.passed ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .foregroundStyle(result.passed ? .green : .red)
            VStack(alignment: .leading, spacing: 2) {
                Text(result.name).font(.subheadline)
                Text(result.attack).font(.caption2).foregroundStyle(.secondary)
                Text(result.observed.description).font(.caption2.monospaced())
            }
        }
    }
}

private struct ConsentSheet: View {
    let challenge: StepUpChallenge
    let decide: (Bool) -> Void

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "person.badge.shield.checkmark")
                .font(.system(size: 44))
            Text("Allow \(challenge.agent.displayName)?")
                .font(.title3.bold())
                .multilineTextAlignment(.center)
            Text("It is asking to act on your behalf with:")
                .font(.subheadline)
            ForEach(challenge.scopes.sorted(), id: \.self) { scope in
                Label(scope.name, systemImage: "exclamationmark.lock").font(.body.monospaced())
            }
            Text("This consent is bound to this agent, these scopes and this device key. It cannot be reused for anything else.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            HStack {
                Button("Deny", role: .cancel) { decide(false) }
                    .buttonStyle(.bordered)
                Button("Allow") { decide(true) }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .presentationDetents([.medium])
    }
}
#endif
