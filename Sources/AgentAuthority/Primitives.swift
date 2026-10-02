import Foundation

/// How an agent reached the app. The broker treats these as different trust
/// classes because they arrive with different evidence about who is driving:
/// an App Intent was routed by the OS, an on-device model tool call was produced
/// by the app's own model, and a remote MCP client is a process the app has
/// never seen before.
public enum AgentKind: String, Sendable, Hashable, Codable, CaseIterable {
    case appIntent
    case onDeviceModel
    case remoteMCP
}

/// An agent identity. Agents get their *own* identity rather than borrowing the
/// user's session: every token names the agent that holds it (the `act` claim in
/// OAuth 2.0 Token Exchange, RFC 8693), so an audit entry can say "agent X did Y
/// on behalf of user Z" instead of "user Z did Y".
public struct AgentPrincipal: Sendable, Hashable, Codable, Identifiable {
    public let id: String
    public let kind: AgentKind
    public let displayName: String

    public init(id: String, kind: AgentKind, displayName: String) {
        self.id = id
        self.kind = kind
        self.displayName = displayName
    }
}

/// Risk tiers are ordered. The broker enforces a floor on top of whatever the
/// policy says: every scope at or above `BrokerConfiguration.mandatoryStepUpTier`
/// needs fresh user consent, even if a (buggy or permissive) policy forgets to
/// ask for it.
public enum RiskTier: Int, Sendable, Hashable, Codable, Comparable, CaseIterable {
    case read = 0
    case write = 1
    case sensitive = 2

    public static func < (lhs: RiskTier, rhs: RiskTier) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A permission. Scopes are compared by name *and* tier, so a forged scope that
/// reuses a sensitive name with a `.read` tier is a different scope and is never
/// granted by a policy that only lists the real one.
public struct Scope: Sendable, Hashable, Codable, Comparable, CustomStringConvertible {
    public let name: String
    public let tier: RiskTier

    public init(_ name: String, tier: RiskTier) {
        self.name = name
        self.tier = tier
    }

    public var description: String { name }

    public static func < (lhs: Scope, rhs: Scope) -> Bool {
        if lhs.name != rhs.name { return lhs.name < rhs.name }
        return lhs.tier < rhs.tier
    }
}

/// A request for the broker to mint a capability token.
public struct DelegationRequest: Sendable {
    /// The user the agent acts for.
    public let subject: String
    public let agent: AgentPrincipal
    /// The resource server / feature boundary the token is valid for.
    public let audience: String
    public let scopes: Set<Scope>
    /// Requested lifetime in seconds. The broker only ever shortens it.
    public let requestedLifetime: TimeInterval
    /// Public key the token will be bound to (proof-of-possession).
    public let proofKey: Data
    /// Present for sub-delegation: the token being attenuated.
    public let parent: CapabilityToken?
    /// Required with `parent`: a DPoP proof, signed by the key the parent token
    /// is bound to, naming `DelegationRequest.delegationMethod` and
    /// `delegationTarget(for: audience)`. Without it, anyone holding a leaked
    /// parent token could re-delegate it to a key of their own choosing — the
    /// exact theft that proof-of-possession exists to stop.
    public let parentProof: DPoPProof?

    public static let delegationMethod = "DELEGATE"
    public static func delegationTarget(for audience: String) -> String { "delegate://\(audience)" }

    public init(
        subject: String,
        agent: AgentPrincipal,
        audience: String,
        scopes: Set<Scope>,
        requestedLifetime: TimeInterval,
        proofKey: Data,
        parent: CapabilityToken? = nil,
        parentProof: DPoPProof? = nil
    ) {
        self.subject = subject
        self.agent = agent
        self.audience = audience
        self.scopes = scopes
        self.requestedLifetime = requestedLifetime
        self.proofKey = proofKey
        self.parent = parent
        self.parentProof = parentProof
    }
}

/// The thing an agent is trying to do with a token.
public struct ProtectedOperation: Sendable, Hashable {
    public let audience: String
    public let method: String
    /// The exact target the DPoP proof must name, e.g. `ledger://payments/initiate`.
    public let target: String
    public let requiredScope: Scope

    public init(audience: String, method: String, target: String, requiredScope: Scope) {
        self.audience = audience
        self.method = method
        self.target = target
        self.requiredScope = requiredScope
    }
}

/// Successful authorization. Returned only after every check passed.
public struct Authorization: Sendable, Hashable {
    public let tokenID: String
    public let grantID: String
    public let agentID: String
    public let actorChain: [String]
    public let subject: String
    public let scope: Scope
    public let target: String
    public let at: Date
}
