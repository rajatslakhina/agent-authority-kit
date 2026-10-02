import Foundation

// MARK: - Policy

public struct PolicyRequest: Sendable {
    public let subject: String
    public let agent: AgentPrincipal
    public let audience: String
    public let scopes: Set<Scope>
    /// 1 for a root grant, 2 for the first sub-delegation, and so on.
    public let chainLength: Int
}

public enum PolicyDecision: Sendable, Equatable {
    case deny(String)
    /// `stepUp` lists scopes that need fresh user consent. The broker adds every
    /// scope at or above its mandatory tier to this set regardless.
    case allow(maxLifetime: TimeInterval, stepUp: Set<Scope>, maxChainLength: Int)
}

/// The product decision about which agent may do what. Kept as a protocol so a
/// team can drive it from remote config, and so tests can inject a deliberately
/// broken policy and prove the broker's own invariants still hold.
public protocol AuthorityPolicy: Sendable {
    func evaluate(_ request: PolicyRequest) -> PolicyDecision
}

/// A table-driven policy: one rule per agent kind, all-or-nothing on scopes.
///
/// All-or-nothing is deliberate. OAuth lets an authorization server silently
/// narrow scope; for an agent that is worse than a refusal, because the agent
/// plans a multi-step task assuming powers it does not have and fails halfway
/// through, after side effects.
public struct StaticAuthorityPolicy: AuthorityPolicy {
    public struct Rule: Sendable {
        public let allowedScopes: Set<Scope>
        public let maxLifetime: TimeInterval
        /// Scopes at or above this tier need step-up (in addition to the broker floor).
        public let stepUpTier: RiskTier
        public let maxChainLength: Int

        public init(allowedScopes: Set<Scope>, maxLifetime: TimeInterval, stepUpTier: RiskTier, maxChainLength: Int) {
            self.allowedScopes = allowedScopes
            self.maxLifetime = maxLifetime
            self.stepUpTier = stepUpTier
            self.maxChainLength = maxChainLength
        }
    }

    public let rules: [AgentKind: Rule]

    public init(rules: [AgentKind: Rule]) {
        self.rules = rules
    }

    public func evaluate(_ request: PolicyRequest) -> PolicyDecision {
        guard let rule = rules[request.agent.kind] else {
            return .deny("no rule for \(request.agent.kind.rawValue)")
        }
        let missing = request.scopes.subtracting(rule.allowedScopes)
        guard missing.isEmpty else {
            let names = missing.sorted().map(\.name).joined(separator: ", ")
            return .deny("\(request.agent.kind.rawValue) may not hold \(names)")
        }
        let stepUp = request.scopes.filter { $0.tier >= rule.stepUpTier }
        return .allow(maxLifetime: rule.maxLifetime, stepUp: stepUp, maxChainLength: rule.maxChainLength)
    }
}

// MARK: - Step-up consent

/// What the user is asked to approve. `grantDigest` binds the answer to exactly
/// this subject, agent, audience, scope set and proof key — a "yes" to reading
/// transactions can never be replayed as a "yes" to initiating a payment.
public struct StepUpChallenge: Sendable, Hashable, Identifiable {
    public let id: String
    public let grantDigest: String
    public let subject: String
    public let agent: AgentPrincipal
    public let audience: String
    public let scopes: Set<Scope>
    public let issuedAt: Date
}

public struct StepUpReceipt: Sendable, Hashable {
    public let challengeID: String
    public let grantDigest: String
    public let approved: Bool
    public let authenticatedAt: Date
    /// e.g. "Face ID", "passcode", "in-app consent". Recorded in the audit log.
    public let method: String

    public init(challengeID: String, grantDigest: String, approved: Bool, authenticatedAt: Date, method: String) {
        self.challengeID = challengeID
        self.grantDigest = grantDigest
        self.approved = approved
        self.authenticatedAt = authenticatedAt
        self.method = method
    }

    public static func answering(_ challenge: StepUpChallenge, approved: Bool, at date: Date, method: String) -> StepUpReceipt {
        StepUpReceipt(challengeID: challenge.id, grantDigest: challenge.grantDigest, approved: approved, authenticatedAt: date, method: method)
    }
}

/// Asks the user. Implementations: LocalAuthentication (Face ID / passcode),
/// an in-app consent sheet, or a scripted authenticator in tests.
///
/// The broker *suspends* on this call — which is exactly where actor
/// reentrancy bites: revocation can land while the user is looking at the
/// prompt. See `AuthorityBroker.exchange(_:)`.
public protocol StepUpAuthenticator: Sendable {
    func authenticate(_ challenge: StepUpChallenge) async -> StepUpReceipt
}

/// Answers every challenge the same way. For tests and for agents that must
/// never be granted sensitive scopes (`approving: false`).
public struct FixedStepUpAuthenticator: StepUpAuthenticator {
    let approve: Bool
    let clock: any AuthorityClock

    public init(approving: Bool, clock: any AuthorityClock) {
        approve = approving
        self.clock = clock
    }

    public func authenticate(_ challenge: StepUpChallenge) async -> StepUpReceipt {
        .answering(challenge, approved: approve, at: clock.now(), method: "fixed")
    }
}
