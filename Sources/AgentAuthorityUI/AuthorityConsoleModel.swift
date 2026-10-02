import Foundation
import Observation
import AgentAuthority

/// Bridges the broker's step-up suspension to an in-app consent prompt.
///
/// Holds the model *weakly*: the model owns the broker, the broker owns this
/// bridge, so a strong reference here would be a retain cycle that keeps the
/// whole console alive forever.
@MainActor
final class ConsentBridge: StepUpAuthenticator {
    weak var model: AuthorityConsoleModel?
    private let clock: any AuthorityClock

    init(clock: any AuthorityClock) {
        self.clock = clock
    }

    nonisolated func authenticate(_ challenge: StepUpChallenge) async -> StepUpReceipt {
        let approved = await ask(challenge)
        return .answering(challenge, approved: approved, at: clock.now(), method: "in-app consent")
    }

    private func ask(_ challenge: StepUpChallenge) async -> Bool {
        // No model (torn down mid-request) means nobody can say yes: decline.
        guard let model else { return false }
        return await model.requestConsent(challenge)
    }
}

/// View model for the authority console. Platform-neutral (Observation only),
/// so its behaviour is unit-tested on Linux; the SwiftUI views are a thin skin.
@MainActor
@Observable
public final class AuthorityConsoleModel {
    public struct ActivityLine: Identifiable, Sendable, Hashable {
        public let id: Int
        public let at: Date
        public let agentID: String
        public let text: String
        public let allowed: Bool
    }

    public struct PendingConsent: Identifiable {
        public let challenge: StepUpChallenge
        fileprivate let continuation: CheckedContinuation<Bool, Never>
        public var id: String { challenge.id }
    }

    public enum JobState: Equatable, Sendable {
        case idle
        case running(step: Int, of: Int)
        case finished(steps: Int)
        case stopped(atStep: Int, reason: String)
    }

    public let broker: AuthorityBroker
    public let policy: StaticAuthorityPolicy
    public let agents: [AgentPrincipal]
    /// Whether new proof keys live in the Secure Enclave (false on Simulator).
    public let hardwareBackedKeys: Bool

    public private(set) var credentials: [String: AgentCredential] = [:]
    /// Agents whose *current* token the console knows to be revoked. The agent
    /// keeps holding the dead token — that is the point: presenting it is what
    /// the broker refuses. Bounded by the number of agents.
    public private(set) var revokedHolders: Set<String> = []
    public private(set) var activity: [ActivityLine] = []
    public private(set) var pendingConsent: PendingConsent?
    public private(set) var job: JobState = .idle
    public private(set) var jobAgentID: String?
    public private(set) var suiteResults: [ScenarioResult] = []
    public private(set) var isRunningSuite = false
    public private(set) var auditEntries: [AuditEntry] = []
    public private(set) var auditStatus: AuditVerification?
    public private(set) var tamperStatus: AuditVerification?
    public private(set) var generation: UInt64 = 0

    static let activityLimit = 200
    private var nextActivityID = 0
    private let clock: any AuthorityClock
    private let jobStepInterval: Duration
    private var jobTask: Task<Void, Never>?

    public init(
        policy: StaticAuthorityPolicy = Ledger.referencePolicy,
        agents: [AgentPrincipal] = Ledger.agents,
        configuration: BrokerConfiguration = BrokerConfiguration(),
        clock: any AuthorityClock = SystemClock(),
        jobStepInterval: Duration = .milliseconds(700)
    ) throws {
        let bridge = ConsentBridge(clock: clock)
        broker = try AuthorityBroker(policy: policy, stepUp: bridge, clock: clock, configuration: configuration)
        self.policy = policy
        self.agents = agents
        self.clock = clock
        self.jobStepInterval = jobStepInterval
        hardwareBackedKeys = ProofKeyFactory.strongestAvailableIsHardwareBacked
        bridge.model = self
    }

    // MARK: Consent

    func requestConsent(_ challenge: StepUpChallenge) async -> Bool {
        // One prompt at a time. A second concurrent request is declined rather
        // than queued: a queued prompt answered "yes" out of context is exactly
        // the consent confusion step-up exists to prevent.
        guard pendingConsent == nil else {
            log(challenge.agent.id, "second consent request while one is open — declined", allowed: false)
            return false
        }
        return await withCheckedContinuation { continuation in
            pendingConsent = PendingConsent(challenge: challenge, continuation: continuation)
        }
    }

    /// The consent sheet's binding. Dismissing the sheet by any route other
    /// than its two buttons counts as "no".
    public var consentSheetItem: PendingConsent? {
        get { pendingConsent }
        set { if newValue == nil { resolveConsent(approved: false) } }
    }

    /// Resolves the open prompt exactly once. Safe to call when none is open.
    public func resolveConsent(approved: Bool) {
        guard let pending = pendingConsent else { return }
        pendingConsent = nil
        pending.continuation.resume(returning: approved)
    }

    // MARK: Agent actions

    public func credential(for agentID: String) -> AgentCredential? { credentials[agentID] }
    public func isRevoked(_ agentID: String) -> Bool { revokedHolders.contains(agentID) }

    /// Grants `scopes` to `agent`, *in addition to* what it already holds: the
    /// agent's token is re-exchanged for one carrying the union, so "Grant pay"
    /// after "Grant read" yields a token that can do both. Because the new token
    /// is a fresh mint, a union that contains a sensitive scope asks for
    /// consent again. If the exchange is refused, the agent keeps the token it
    /// had. Requesting scopes the agent already holds is a no-op.
    public func request(_ scopes: Set<Scope>, for agent: AgentPrincipal) async {
        let held = revokedHolders.contains(agent.id) ? [] : (credentials[agent.id]?.token.scopes ?? [])
        if !scopes.isEmpty, scopes.isSubset(of: held) {
            log(agent.id, "already holds \(scopes.sorted().map(\.name).joined(separator: ", "))", allowed: true)
            return
        }
        let key = ProofKeyFactory.strongestAvailable()
        await mint(DelegationRequest(
            subject: Ledger.subject, agent: agent, audience: Ledger.audience, scopes: held.union(scopes),
            requestedLifetime: 300, proofKey: key.publicKey
        ), key: key)
    }

    /// `parent` delegates an attenuated slice of its own token to `child`,
    /// proving possession of the parent's key as it does so.
    public func delegate(_ scopes: Set<Scope>, from parent: AgentPrincipal, to child: AgentPrincipal) async {
        guard let parentCredential = credentials[parent.id] else {
            log(child.id, "cannot delegate: \(parent.displayName) holds no token", allowed: false)
            return
        }
        let key = ProofKeyFactory.strongestAvailable()
        do {
            let request = try parentCredential.delegate(scopes, to: child, childKey: key, lifetime: 300, at: clock.now())
            await mint(request, key: key)
        } catch {
            log(child.id, "cannot delegate: \(error)", allowed: false)
        }
    }

    private func mint(_ request: DelegationRequest, key: any ProofKey) async {
        do {
            let token = try await broker.exchange(request)
            credentials[request.agent.id] = AgentCredential(token: token, key: key)
            revokedHolders.remove(request.agent.id)
            let names = token.scopes.sorted().map(\.name).joined(separator: ", ")
            log(request.agent.id, "token issued: \(names) (chain \(token.actorChain.joined(separator: " → ")))", allowed: true)
        } catch {
            log(request.agent.id, "token refused: \(error)", allowed: false)
        }
        await refreshAudit()
    }

    @discardableResult
    public func invoke(_ operation: ProtectedOperation, as agent: AgentPrincipal) async -> Bool {
        let denial = await attempt(operation, as: agent)
        await refreshAudit()
        return denial == nil
    }

    /// nil on success, otherwise the reason it was refused.
    private func attempt(_ operation: ProtectedOperation, as agent: AgentPrincipal) async -> String? {
        guard let credential = credentials[agent.id] else {
            let reason = "no token"
            log(agent.id, "\(operation.target): \(reason)", allowed: false)
            return reason
        }
        do {
            let presentation = try credential.present(for: operation, at: clock.now())
            _ = try await broker.authorize(presentation, for: operation)
            log(agent.id, "\(operation.method) \(operation.target)", allowed: true)
            return nil
        } catch {
            let reason = String(describing: error)
            log(agent.id, "\(operation.target): \(reason)", allowed: false)
            return reason
        }
    }

    // MARK: In-flight job

    /// Runs a multi-step task that re-authorizes on every step — so a
    /// revocation stops it at the next step, not at the next token.
    ///
    /// A cancelled run may still be suspended inside `authorize` when the next
    /// run starts; it checks cancellation after every suspension and exits
    /// without touching `job`.
    public func startJob(as agent: AgentPrincipal, steps: Int = 8) {
        guard steps >= 1 else { return }
        if case .running = job { return }
        jobAgentID = agent.id
        job = .running(step: 0, of: steps)
        let interval = jobStepInterval
        jobTask = Task { [weak self] in
            for step in 1...steps {
                guard let self, !Task.isCancelled else { return }
                self.job = .running(step: step, of: steps)
                let denial = await self.attempt(Ledger.listTransactions, as: agent)
                await self.refreshAudit()
                guard !Task.isCancelled else { return }
                if let denial {
                    self.job = .stopped(atStep: step, reason: denial)
                    return
                }
                try? await Task.sleep(for: interval)
            }
            guard let self, !Task.isCancelled else { return }
            self.job = .finished(steps: steps)
        }
    }

    public func cancelJob() {
        jobTask?.cancel()
        jobTask = nil
        if case .running(let step, _) = job { job = .stopped(atStep: step, reason: "cancelled") }
    }

    // MARK: Revocation

    public func revoke(_ agent: AgentPrincipal) async {
        await broker.revokeAgent(agent.id)
        // The agent's token and every token delegated through it are dead now.
        for (holder, credential) in credentials where credential.token.actorChain.contains(agent.id) {
            revokedHolders.insert(holder)
        }
        log(agent.id, "agent revoked (and everything it delegated)", allowed: false)
        await refreshAudit()
    }

    public func revokeAll() async {
        await broker.revokeAll()
        revokedHolders.formUnion(credentials.keys)
        log("-", "kill switch: every outstanding token revoked", allowed: false)
        await refreshAudit()
    }

    // MARK: Suite and audit

    public func runSuite() async {
        guard !isRunningSuite else { return }
        isRunningSuite = true
        suiteResults = await AdversarialSuite.run(policy: policy)
        isRunningSuite = false
    }

    public var suitePassCount: Int { suiteResults.filter(\.passed).count }

    public func refreshAudit() async {
        let snapshot = await broker.auditSnapshot()
        auditEntries = snapshot.entries
        auditStatus = await broker.verify(snapshot)
        generation = await broker.generation
    }

    /// Edits one entry of a *copy* of the log, the way an attacker with write
    /// access to storage but not the key would, and verifies the copy.
    public func demonstrateTamper() async {
        var snapshot = await broker.auditSnapshot()
        guard !snapshot.entries.isEmpty else {
            tamperStatus = nil
            log("-", "audit log is empty — nothing to tamper with", allowed: false)
            return
        }
        let index = snapshot.entries.count / 2
        snapshot.entries[index] = snapshot.entries[index].tampered(detail: "nothing to see here")
        tamperStatus = await broker.verify(snapshot)
    }

    // MARK: Activity

    private func log(_ agentID: String, _ text: String, allowed: Bool) {
        activity.append(ActivityLine(id: nextActivityID, at: clock.now(), agentID: agentID, text: text, allowed: allowed))
        nextActivityID = nextActivityID == Int.max ? 0 : nextActivityID + 1
        let overflow = activity.count - Self.activityLimit
        if overflow > 0 { activity.removeFirst(overflow) }
    }
}
