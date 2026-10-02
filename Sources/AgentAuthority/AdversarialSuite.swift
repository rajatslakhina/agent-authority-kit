import Foundation

/// A step-up authenticator driven by a closure. Lets a scenario model a user
/// who approves, declines, approves too late, or — the interesting one — a
/// revocation that lands while the prompt is on screen.
public struct ScriptedStepUp: StepUpAuthenticator {
    private let script: @Sendable (StepUpChallenge) async -> StepUpReceipt

    public init(_ script: @escaping @Sendable (StepUpChallenge) async -> StepUpReceipt) {
        self.script = script
    }

    public func authenticate(_ challenge: StepUpChallenge) async -> StepUpReceipt {
        await script(challenge)
    }
}

/// A household-ledger fixture: the scopes, agents and operations the suite
/// and the demo app share.
public enum Ledger {
    public static let audience = "ledger"
    public static let subject = "user-42"

    public static let readTransactions = Scope("transactions.read", tier: .read)
    public static let categorize = Scope("transactions.categorize", tier: .write)
    public static let initiatePayment = Scope("payments.initiate", tier: .sensitive)
    public static let exportData = Scope("data.export", tier: .sensitive)
    public static let allScopes: [Scope] = [readTransactions, categorize, initiatePayment, exportData]

    public static let siri = AgentPrincipal(id: "siri-intent", kind: .appIntent, displayName: "Siri (App Intent)")
    public static let budgetModel = AgentPrincipal(id: "budget-model", kind: .onDeviceModel, displayName: "On-device budget model")
    public static let desktopMCP = AgentPrincipal(id: "mcp-desktop", kind: .remoteMCP, displayName: "Desktop MCP client")
    public static let agents: [AgentPrincipal] = [siri, budgetModel, desktopMCP]

    public static let listTransactions = ProtectedOperation(audience: audience, method: "GET", target: "ledger://transactions/list", requiredScope: readTransactions)
    public static let recategorize = ProtectedOperation(audience: audience, method: "PATCH", target: "ledger://transactions/category", requiredScope: categorize)
    public static let pay = ProtectedOperation(audience: audience, method: "POST", target: "ledger://payments/initiate", requiredScope: initiatePayment)
    public static let export = ProtectedOperation(audience: audience, method: "POST", target: "ledger://data/export", requiredScope: exportData)

    public static func operation(for scope: Scope) -> ProtectedOperation? {
        [listTransactions, recategorize, pay, export].first { $0.requiredScope == scope }
    }

    /// The reference policy: Siri may do everything (sensitive scopes behind
    /// consent); the on-device model may read, categorize and pay; a remote MCP
    /// client may only read, and may not re-delegate.
    public static let referencePolicy = StaticAuthorityPolicy(rules: [
        .appIntent: .init(allowedScopes: Set(allScopes), maxLifetime: 300, stepUpTier: .sensitive, maxChainLength: 2),
        .onDeviceModel: .init(allowedScopes: [readTransactions, categorize, initiatePayment], maxLifetime: 120, stepUpTier: .sensitive, maxChainLength: 2),
        .remoteMCP: .init(allowedScopes: [readTransactions], maxLifetime: 600, stepUpTier: .sensitive, maxChainLength: 1),
    ])
}

public enum ScenarioOutcome: Sendable, Hashable, CustomStringConvertible {
    case allowed
    case denied(AuthorityError)
    case harnessFailure(String)

    public var description: String {
        switch self {
        case .allowed: return "allowed"
        case .denied(let e): return "denied — \(e)"
        case .harnessFailure(let m): return "harness failure — \(m)"
        }
    }
}

public struct ScenarioResult: Sendable, Hashable, Identifiable {
    public let id: Int
    public let name: String
    public let attack: String
    /// `nil` means the scenario expects the call to be allowed.
    public let expectedDenial: String?
    public let observed: ScenarioOutcome

    public var passed: Bool {
        switch observed {
        case .allowed: return expectedDenial == nil
        case .denied(let error): return expectedDenial == error.code
        case .harnessFailure: return false
        }
    }
}

/// Replays adversarial tool-call sequences against a fresh broker per
/// scenario and reports which ones the broker stopped, and with what reason.
///
/// Expectations are compared by error *case*, not just "it threw": a stolen
/// token refused for the wrong reason (say, an expiry that happened to apply)
/// would pass a looser suite while the key-binding check was broken.
public enum AdversarialSuite {
    private struct Environment {
        let broker: AuthorityBroker
        let clock: ManualClock
    }

    /// Set exactly once, before the broker it points at is used, so a step-up
    /// script can reach the broker that is awaiting it.
    private final class BrokerSlot: @unchecked Sendable {
        // @unchecked: written once during setup, before any concurrent reader exists.
        var broker: AuthorityBroker?
    }

    private struct Scenario: Sendable {
        let name: String
        let attack: String
        let expectedDenial: String?
        let stepUp: @Sendable (ManualClock, BrokerSlot) -> any StepUpAuthenticator
        let body: @Sendable (Environment) async throws -> Void
    }

    private static func approving(_ clock: ManualClock, _: BrokerSlot) -> any StepUpAuthenticator {
        FixedStepUpAuthenticator(approving: true, clock: clock)
    }

    private static func issue(
        _ env: Environment, _ agent: AgentPrincipal, _ scopes: Set<Scope>,
        parent: AgentCredential? = nil, key: any ProofKey = SoftwareProofKey(),
        lifetime: TimeInterval = 300, audience: String = Ledger.audience
    ) async throws -> AgentCredential {
        let request: DelegationRequest
        if let parent {
            request = try parent.delegate(scopes, to: agent, childKey: key, lifetime: lifetime, at: env.clock.now())
        } else {
            request = DelegationRequest(
                subject: Ledger.subject, agent: agent, audience: audience, scopes: scopes,
                requestedLifetime: lifetime, proofKey: key.publicKey
            )
        }
        let token = try await env.broker.exchange(request)
        return AgentCredential(token: token, key: key)
    }

    private static func call(_ env: Environment, _ credential: AgentCredential, _ op: ProtectedOperation) async throws {
        _ = try await env.broker.authorize(try credential.present(for: op, at: env.clock.now()), for: op)
    }

    private static let scenarios: [Scenario] = [
        Scenario(name: "Baseline read", attack: "None — a bound token with a fresh proof.", expectedDenial: nil, stepUp: approving) { env in
            let c = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            try await call(env, c, Ledger.listTransactions)
        },
        Scenario(name: "Baseline payment with consent", attack: "None — sensitive scope, user approves.", expectedDenial: nil, stepUp: approving) { env in
            let c = try await issue(env, Ledger.siri, [Ledger.initiatePayment])
            try await call(env, c, Ledger.pay)
        },
        Scenario(name: "Stolen token", attack: "Token exfiltrated; attacker signs proofs with their own key.", expectedDenial: "proofKeyMismatch", stepUp: approving) { env in
            let c = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions])
            try await call(env, AgentCredential(token: c.token, key: SoftwareProofKey()), Ledger.listTransactions)
        },
        Scenario(name: "Proof replay", attack: "A captured request is sent a second time.", expectedDenial: "proofReplayed", stepUp: approving) { env in
            let c = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            let p = try c.present(for: Ledger.listTransactions, at: env.clock.now())
            _ = try await env.broker.authorize(p, for: Ledger.listTransactions)
            _ = try await env.broker.authorize(p, for: Ledger.listTransactions)
        },
        Scenario(name: "Proof lifted to another endpoint", attack: "A valid read proof is replayed against a write endpoint the token also covers.", expectedDenial: "proofTargetMismatch", stepUp: approving) { env in
            let c = try await issue(env, Ledger.siri, [Ledger.readTransactions, Ledger.categorize])
            let p = try c.present(for: Ledger.listTransactions, at: env.clock.now())
            _ = try await env.broker.authorize(p, for: Ledger.recategorize)
        },
        Scenario(name: "Wrong audience", attack: "A ledger token is presented to another feature boundary.", expectedDenial: "audienceMismatch", stepUp: approving) { env in
            let c = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            let op = ProtectedOperation(audience: "messages", method: "GET", target: "messages://inbox", requiredScope: Ledger.readTransactions)
            try await call(env, c, op)
        },
        Scenario(name: "Scope escalation", attack: "A read-only token is used to initiate a payment.", expectedDenial: "scopeNotGranted", stepUp: approving) { env in
            let c = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions])
            try await call(env, c, Ledger.pay)
        },
        Scenario(name: "Token edited in transit", attack: "Payment scope is added to a read token after minting.", expectedDenial: "tokenSignatureInvalid", stepUp: approving) { env in
            let c = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions])
            let forged = AgentCredential(token: c.token.tampered(scopes: [Ledger.readTransactions, Ledger.initiatePayment]), key: c.key)
            try await call(env, forged, Ledger.pay)
        },
        Scenario(name: "Sub-delegation widening", attack: "Siri delegates to the model and asks for more than it holds.", expectedDenial: "delegationNotAttenuated", stepUp: approving) { env in
            let parent = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            _ = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions, Ledger.categorize], parent: parent)
        },
        Scenario(name: "Stolen token re-delegated", attack: "A leaked token is sub-delegated to a key the attacker controls.", expectedDenial: "proofKeyMismatch", stepUp: approving) { env in
            let victim = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            let attacker = AgentCredential(token: victim.token, key: SoftwareProofKey())
            _ = try await issue(env, AgentPrincipal(id: "rogue", kind: .appIntent, displayName: "Rogue"), [Ledger.readTransactions], parent: attacker)
        },
        Scenario(name: "Delegation to a remote client", attack: "Siri hands its token on to a remote MCP client (policy: chain length 1).", expectedDenial: "delegationTooDeep", stepUp: approving) { env in
            let parent = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            _ = try await issue(env, Ledger.desktopMCP, [Ledger.readTransactions], parent: parent)
        },
        Scenario(name: "Remote client asks to pay", attack: "A remote MCP client requests a payment scope.", expectedDenial: "policyDenied", stepUp: approving) { env in
            _ = try await issue(env, Ledger.desktopMCP, [Ledger.initiatePayment])
        },
        Scenario(name: "User declines", attack: "Agent requests a payment; the user says no.", expectedDenial: "stepUpDeclined", stepUp: { clock, _ in FixedStepUpAuthenticator(approving: false, clock: clock) }) { env in
            _ = try await issue(env, Ledger.budgetModel, [Ledger.initiatePayment])
        },
        Scenario(name: "Consent for another grant", attack: "A receipt bound to a different grant is offered.", expectedDenial: "stepUpMismatch", stepUp: { clock, _ in
            ScriptedStepUp { c in StepUpReceipt(challengeID: c.id, grantDigest: "a-different-grant", approved: true, authenticatedAt: clock.now(), method: "scripted") }
        }) { env in
            _ = try await issue(env, Ledger.siri, [Ledger.exportData])
        },
        Scenario(name: "Stale consent", attack: "The user authenticated, then the grant sat for three minutes.", expectedDenial: "stepUpStale", stepUp: { clock, _ in
            ScriptedStepUp { c in
                let receipt = StepUpReceipt.answering(c, approved: true, at: clock.now(), method: "scripted")
                clock.advance(by: 180)
                return receipt
            }
        }) { env in
            _ = try await issue(env, Ledger.siri, [Ledger.initiatePayment])
        },
        Scenario(name: "Revocation during consent", attack: "The agent is revoked while the consent prompt is on screen.", expectedDenial: "revokedDuringStepUp", stepUp: { clock, slot in
            ScriptedStepUp { c in
                await slot.broker?.revokeAgent(c.agent.id)
                return .answering(c, approved: true, at: clock.now(), method: "scripted")
            }
        }) { env in
            _ = try await issue(env, Ledger.siri, [Ledger.initiatePayment])
        },
        Scenario(name: "Expired token", attack: "A token is used after its lifetime.", expectedDenial: "tokenExpired", stepUp: approving) { env in
            let c = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions], lifetime: 60)
            env.clock.advance(by: 61)
            try await call(env, c, Ledger.listTransactions)
        },
        Scenario(name: "In-flight revocation", attack: "Agent is mid-task when the user revokes it.", expectedDenial: "revoked", stepUp: approving) { env in
            let c = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions])
            try await call(env, c, Ledger.listTransactions)
            env.clock.advance(by: 1)
            await env.broker.revokeAgent(Ledger.budgetModel.id)
            try await call(env, c, Ledger.listTransactions)
        },
        Scenario(name: "Revoked delegator", attack: "Siri is revoked; the model still holds a token Siri delegated.", expectedDenial: "revoked", stepUp: approving) { env in
            let parent = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            let child = try await issue(env, Ledger.budgetModel, [Ledger.readTransactions], parent: parent)
            env.clock.advance(by: 1)
            await env.broker.revokeAgent(Ledger.siri.id)
            try await call(env, child, Ledger.listTransactions)
        },
        Scenario(name: "Kill switch", attack: "Every outstanding token is revoked at once.", expectedDenial: "revoked", stepUp: approving) { env in
            let c = try await issue(env, Ledger.siri, [Ledger.readTransactions])
            await env.broker.revokeAll()
            try await call(env, c, Ledger.listTransactions)
        },
    ]

    public static var scenarioCount: Int { scenarios.count }

    /// Runs every scenario against a fresh broker built from `policy`.
    /// Inject a deliberately broken policy to see which scenarios the broker's
    /// own invariants still hold and which ones depend on the policy.
    public static func run(
        policy: any AuthorityPolicy = Ledger.referencePolicy,
        configuration: BrokerConfiguration = BrokerConfiguration()
    ) async -> [ScenarioResult] {
        var results: [ScenarioResult] = []
        for (index, scenario) in scenarios.enumerated() {
            let clock = ManualClock()
            let slot = BrokerSlot()
            let outcome: ScenarioOutcome
            do {
                let broker = try AuthorityBroker(policy: policy, stepUp: scenario.stepUp(clock, slot), clock: clock, configuration: configuration)
                slot.broker = broker
                try await scenario.body(Environment(broker: broker, clock: clock))
                outcome = .allowed
            } catch let error as AuthorityError {
                outcome = .denied(error)
            } catch {
                outcome = .harnessFailure(String(describing: error))
            }
            results.append(ScenarioResult(id: index, name: scenario.name, attack: scenario.attack, expectedDenial: scenario.expectedDenial, observed: outcome))
        }
        return results
    }
}
