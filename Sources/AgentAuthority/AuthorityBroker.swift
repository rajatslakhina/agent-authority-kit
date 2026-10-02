import Foundation

public struct BrokerConfiguration: Sendable, Equatable {
    /// Upper bound on any token's lifetime, whatever the policy says. Also the
    /// retention period for revocation entries (see `RevocationState`).
    public var hardMaxLifetime: TimeInterval = 900
    /// How long a DPoP proof is accepted after its `iat`.
    public var proofWindow: TimeInterval = 60
    /// How far in the *future* a proof's `iat` may be (device clock drift).
    public var clockSkew: TimeInterval = 5
    /// A step-up receipt older than this when the broker resumes is refused.
    public var stepUpFreshness: TimeInterval = 120
    /// Broker floor: scopes at or above this tier always need step-up.
    public var mandatoryStepUpTier: RiskTier = .sensitive
    /// Longest `act` chain the broker will ever mint, whatever the policy says.
    public var hardMaxChainLength: Int = 3
    public var replayCacheCapacity: Int = 4096
    public var revocationCapacity: Int = 1024
    public var auditCapacity: Int = 512

    public init() {}

    func validate() throws {
        let durations: [(String, TimeInterval)] = [
            ("hardMaxLifetime", hardMaxLifetime), ("proofWindow", proofWindow),
            ("stepUpFreshness", stepUpFreshness),
        ]
        for (name, value) in durations where !value.isUsableDuration {
            throw AuthorityError.invalidConfiguration("\(name) must be finite and > 0")
        }
        guard clockSkew.isFinite, clockSkew >= 0 else {
            throw AuthorityError.invalidConfiguration("clockSkew must be finite and >= 0")
        }
        let capacities: [(String, Int)] = [
            ("hardMaxChainLength", hardMaxChainLength), ("replayCacheCapacity", replayCacheCapacity),
            ("revocationCapacity", revocationCapacity), ("auditCapacity", auditCapacity),
        ]
        for (name, value) in capacities where value < 1 {
            throw AuthorityError.invalidConfiguration("\(name) must be >= 1")
        }
    }
}

/// The broker's secrets. On device these belong in the Keychain
/// (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`); the demo generates
/// them per launch.
public struct BrokerKeys: Sendable {
    let token: Data
    let audit: Data

    public init(token: Data, audit: Data) throws {
        guard token.count >= 32, audit.count >= 32 else {
            throw AuthorityError.invalidConfiguration("keys must be at least 256 bits")
        }
        self.token = token
        self.audit = audit
    }

    public static func random() -> BrokerKeys {
        // Both keys are exactly 32 bytes, so the validating init cannot fail;
        // the memberwise path avoids a `try!`.
        BrokerKeys(unchecked: Digest.randomKey(), audit: Digest.randomKey())
    }

    private init(unchecked token: Data, audit: Data) {
        self.token = token
        self.audit = audit
    }
}

/// Exchanges agent invocations for short-lived capability tokens and checks
/// every presentation of one.
///
/// Why an actor: minting, revocation and the replay cache must be serialized
/// with each other — a token minted concurrently with `revokeAll()` must land
/// either wholly before it (and die) or wholly after it (and carry the new
/// generation). The one suspension point is step-up consent, and it is handled
/// explicitly: see `exchange(_:)`.
public actor AuthorityBroker {
    private let policy: any AuthorityPolicy
    private let stepUp: any StepUpAuthenticator
    private let clock: any AuthorityClock
    public let configuration: BrokerConfiguration
    private let keys: BrokerKeys

    private var revocation: RevocationState
    private var replay: ReplayCache
    private var audit: AuditLog

    public init(
        policy: any AuthorityPolicy,
        stepUp: any StepUpAuthenticator,
        clock: any AuthorityClock = SystemClock(),
        configuration: BrokerConfiguration = BrokerConfiguration(),
        keys: BrokerKeys = .random()
    ) throws {
        try self.init(policy: policy, stepUp: stepUp, clock: clock, configuration: configuration, keys: keys, initialGeneration: 0)
    }

    /// Internal so tests can start near `UInt64.max` and exercise sealing.
    init(
        policy: any AuthorityPolicy,
        stepUp: any StepUpAuthenticator,
        clock: any AuthorityClock,
        configuration: BrokerConfiguration,
        keys: BrokerKeys,
        initialGeneration: UInt64
    ) throws {
        try configuration.validate()
        self.policy = policy
        self.stepUp = stepUp
        self.clock = clock
        self.configuration = configuration
        self.keys = keys
        revocation = RevocationState(capacity: configuration.revocationCapacity, retention: configuration.hardMaxLifetime, generation: initialGeneration)
        replay = ReplayCache(capacity: configuration.replayCacheCapacity)
        audit = AuditLog(capacity: configuration.auditCapacity, key: keys.audit)
    }

    // MARK: Exchange

    /// Mints a token for `request`, or throws the reason it will not.
    ///
    /// Reentrancy: if any requested scope needs step-up, this method suspends on
    /// `StepUpAuthenticator.authenticate`. While suspended, other calls run on
    /// the actor — including `revokeAgent` and `revokeAll`. Everything decided
    /// before the `await` is therefore re-checked after it against a
    /// revocation *witness* captured before it; a token is never minted on the
    /// strength of a pre-suspension check.
    public func exchange(_ request: DelegationRequest) async throws -> CapabilityToken {
        do {
            return try await performExchange(request)
        } catch {
            record(.denied, agent: request.agent.id, subject: request.subject, "exchange: \(error)")
            throw error
        }
    }

    private func performExchange(_ request: DelegationRequest) async throws(AuthorityError) -> CapabilityToken {
        let start = clock.now()
        guard !revocation.sealed else { throw .brokerSealed }
        guard !request.subject.isEmpty, !request.agent.id.isEmpty, !request.audience.isEmpty else {
            throw .invalidRequest("subject, agent and audience are required")
        }
        guard !request.scopes.isEmpty else { throw .invalidRequest("no scopes requested") }
        guard request.requestedLifetime.isUsableDuration else {
            throw .invalidRequest("lifetime must be finite and > 0")
        }
        guard ProofVerifier.isWellFormedPublicKey(request.proofKey) else {
            throw .invalidRequest("proof key is not a P-256 public key")
        }

        var chain = [request.agent.id]
        var ancestors: [String] = []
        var grantID = UUID().uuidString
        if let parent = request.parent {
            if let problem = problem(with: parent, at: start) { throw .parentInvalid(problem) }
            guard parent.subject == request.subject, parent.audience == request.audience else {
                throw .invalidRequest("sub-delegation must keep subject and audience")
            }
            // The caller must prove it holds the parent's key. A leaked parent
            // token alone must not be re-delegatable to an attacker's key.
            guard let parentProof = request.parentProof else {
                throw .invalidRequest("sub-delegation requires proof of possession of the parent token")
            }
            try verifyProof(
                parentProof, for: parent, method: DelegationRequest.delegationMethod,
                target: DelegationRequest.delegationTarget(for: parent.audience), now: start
            )
            guard request.scopes.isSubset(of: parent.scopes) else { throw .delegationNotAttenuated }
            guard !parent.actorChain.contains(request.agent.id) else {
                throw .invalidRequest("delegation cycle through \(request.agent.id)")
            }
            chain = parent.actorChain + [request.agent.id]
            ancestors = parent.ancestorTokenIDs + [parent.id]
            grantID = parent.grantID
        }
        guard chain.count <= configuration.hardMaxChainLength else {
            throw .delegationTooDeep(limit: configuration.hardMaxChainLength)
        }

        let decision = policy.evaluate(PolicyRequest(
            subject: request.subject, agent: request.agent, audience: request.audience,
            scopes: request.scopes, chainLength: chain.count
        ))
        let maxLifetime: TimeInterval
        let policyStepUp: Set<Scope>
        let maxChain: Int
        switch decision {
        case .deny(let reason):
            throw .policyDenied(reason)
        case let .allow(lifetime, stepUpScopes, chainLimit):
            maxLifetime = lifetime
            policyStepUp = stepUpScopes
            maxChain = chainLimit
        }
        // The broker does not trust the policy to be well-formed.
        guard maxLifetime.isUsableDuration else { throw .policyViolation("lifetime must be finite and > 0") }
        guard policyStepUp.isSubset(of: request.scopes) else { throw .policyViolation("step-up for unrequested scopes") }
        guard chain.count <= maxChain else { throw .delegationTooDeep(limit: max(maxChain, 0)) }

        // All three are finite and > 0, so `lifetime` is too.
        let lifetime = min(request.requestedLifetime, maxLifetime, configuration.hardMaxLifetime)
        let floor = request.scopes.filter { $0.tier >= configuration.mandatoryStepUpTier }
        let stepUpScopes = policyStepUp.union(floor)
        let thumbprint = ProofVerifier.thumbprint(of: request.proofKey)

        var consent = "none"
        if !stepUpScopes.isEmpty {
            let witness = revocation.witness(actors: chain, grantID: request.parent?.grantID, parentTokenID: request.parent?.id)
            let challenge = StepUpChallenge(
                id: UUID().uuidString,
                grantDigest: grantDigest(request, thumbprint: thumbprint),
                subject: request.subject, agent: request.agent, audience: request.audience,
                scopes: stepUpScopes, issuedAt: start
            )
            let receipt = await stepUp.authenticate(challenge)
            // ---- Suspension point. Actor state may have changed. ----
            guard !Task.isCancelled else { throw .cancelled }
            guard revocation.witness(actors: chain, grantID: request.parent?.grantID, parentTokenID: request.parent?.id) == witness else {
                throw .revokedDuringStepUp
            }
            guard receipt.challengeID == challenge.id, receipt.grantDigest == challenge.grantDigest else {
                throw .stepUpMismatch
            }
            guard receipt.approved else {
                record(.stepUp, agent: request.agent.id, subject: request.subject, "declined via \(receipt.method)")
                throw .stepUpDeclined
            }
            let resumed = clock.now()
            guard receipt.authenticatedAt >= challenge.issuedAt,
                  receipt.authenticatedAt <= resumed,
                  resumed.timeIntervalSince(receipt.authenticatedAt) <= configuration.stepUpFreshness
            else { throw .stepUpStale }
            consent = receipt.method
            record(.stepUp, agent: request.agent.id, subject: request.subject,
                   "approved via \(receipt.method) for \(names(stepUpScopes))")
        }

        let issuedAt = clock.now()
        var expiresAt = issuedAt.addingTimeInterval(lifetime)
        if let parent = request.parent {
            // Re-checked after any suspension: the parent may have expired or
            // been revoked while the user was deciding.
            if let problem = problem(with: parent, at: issuedAt) { throw .parentInvalid(problem) }
            expiresAt = min(expiresAt, parent.expiresAt)
        }
        // Unreachable while the re-check above stands (an unexpired parent
        // leaves positive lifetime); kept as a backstop with its own message so
        // a test can tell the two apart.
        guard expiresAt > issuedAt else { throw .parentInvalid("no lifetime left") }

        let unsigned = CapabilityToken(
            id: UUID().uuidString, grantID: grantID, subject: request.subject, actorChain: chain,
            ancestorTokenIDs: ancestors, agentKind: request.agent.kind, audience: request.audience, scopes: request.scopes,
            issuedAt: issuedAt, expiresAt: expiresAt, generation: revocation.generation,
            confirmationThumbprint: thumbprint, mac: Data()
        )
        let token = CapabilityToken(
            id: unsigned.id, grantID: unsigned.grantID, subject: unsigned.subject, actorChain: unsigned.actorChain,
            ancestorTokenIDs: unsigned.ancestorTokenIDs, agentKind: unsigned.agentKind, audience: unsigned.audience, scopes: unsigned.scopes,
            issuedAt: unsigned.issuedAt, expiresAt: unsigned.expiresAt, generation: unsigned.generation,
            confirmationThumbprint: unsigned.confirmationThumbprint,
            mac: Digest.mac(unsigned.signingInput, key: keys.token)
        )
        record(request.parent == nil ? .issued : .delegated, agent: request.agent.id, subject: request.subject,
               "\(names(request.scopes)) @\(request.audience) ttl=\(String(format: "%.0f", lifetime))s chain=\(chain.joined(separator: ">")) consent=\(consent)")
        return token
    }

    // MARK: Authorize

    /// Checks one presentation against one operation. Cheap, synchronous inside
    /// the actor, and called on every protected step — that is what makes
    /// revocation reach *in-flight* agent sessions rather than only new ones.
    public func authorize(_ presentation: Presentation, for operation: ProtectedOperation) throws -> Authorization {
        let token = presentation.token
        do {
            let result = try check(presentation, for: operation)
            record(.authorized, agent: token.holderID, subject: token.subject, "\(operation.method) \(operation.target)")
            return result
        } catch {
            record(.denied, agent: token.holderID, subject: token.subject, "\(operation.target): \(error)")
            throw error
        }
    }

    private func check(_ presentation: Presentation, for operation: ProtectedOperation) throws(AuthorityError) -> Authorization {
        let now = clock.now()
        let token = presentation.token
        let proof = presentation.proof
        guard !revocation.sealed else { throw .brokerSealed }
        guard Digest.verifyMAC(token.mac, for: token.signingInput, key: keys.token) else { throw .tokenSignatureInvalid }
        guard now < token.expiresAt else { throw .tokenExpired }
        if let reason = revocation.reason(for: token) { throw .revoked(reason) }
        guard token.audience == operation.audience else { throw .audienceMismatch }
        guard token.scopes.contains(operation.requiredScope) else { throw .scopeNotGranted(operation.requiredScope.name) }

        try verifyProof(proof, for: token, method: operation.method, target: operation.target, now: now)
        return Authorization(
            tokenID: token.id, grantID: token.grantID, agentID: token.holderID, actorChain: token.actorChain,
            subject: token.subject, scope: operation.requiredScope, target: operation.target, at: now
        )
    }

    /// DPoP checks shared by `authorize` and sub-delegation: key binding,
    /// signature, token binding, method/target, freshness, single use.
    private func verifyProof(
        _ proof: DPoPProof, for token: CapabilityToken, method: String, target: String, now: Date
    ) throws(AuthorityError) {
        guard ProofVerifier.thumbprint(of: proof.publicKey) == token.confirmationThumbprint else { throw .proofKeyMismatch }
        guard ProofVerifier.isValid(signature: proof.signature, for: proof.signingInput, publicKey: proof.publicKey) else {
            throw .proofSignatureInvalid
        }
        guard proof.tokenHash == token.hashForProof else { throw .proofTokenBindingMismatch }
        guard proof.method == method, proof.target == target else { throw .proofTargetMismatch }
        let age = now.timeIntervalSince(proof.issuedAt)
        guard age.isFinite, age <= configuration.proofWindow, age >= -configuration.clockSkew else { throw .proofStale }

        // Last, so malformed proofs can never fill the cache.
        switch replay.insert(proof.id, expiresAt: proof.issuedAt.addingTimeInterval(configuration.proofWindow), now: now) {
        case .fresh: break
        case .replayed: throw .proofReplayed
        case .saturated: throw .replayCacheSaturated
        }
    }

    // MARK: Revocation

    /// Kills this token and every token delegated from it (directly or not).
    public func revokeToken(_ id: String) {
        let outcome = revocation.revokeToken(id, at: clock.now())
        record(.revoked, agent: "-", subject: "-", "token \(id.prefix(8))")
        recordFallback(outcome)
    }

    /// Kills the root token and every token sub-delegated from it.
    public func revokeGrant(_ id: String) {
        let outcome = revocation.revokeGrant(id, at: clock.now())
        record(.revoked, agent: "-", subject: "-", "grant \(id.prefix(8))")
        recordFallback(outcome)
    }

    /// Kills every token this agent holds *or delegated*, issued up to now.
    /// An instant, not a ban: tokens issued to the agent afterwards are valid.
    public func revokeAgent(_ id: String) {
        let outcome = revocation.revokeAgent(id, at: clock.now())
        record(.revoked, agent: id, subject: "-", "agent \(id)")
        recordFallback(outcome)
    }

    private func recordFallback(_ outcome: RevocationState.InsertOutcome) {
        switch outcome {
        case .recorded: break
        case .revokedAllAtCapacity:
            record(.revoked, agent: "-", subject: "-", "all (revocation table full; generation \(revocation.generation))")
        case .sealed:
            record(.revoked, agent: "-", subject: "-", "generation exhausted: broker sealed")
        }
    }

    /// The kill switch.
    public func revokeAll() {
        let ok = revocation.revokeAll()
        record(.revoked, agent: "-", subject: "-", ok ? "all (generation \(revocation.generation))" : "generation exhausted: broker sealed")
    }

    // MARK: Introspection

    public var generation: UInt64 { revocation.generation }
    public var isSealed: Bool { revocation.sealed }
    public var revocationEntryCount: Int { revocation.entryCount }
    public var replayCacheCount: Int { replay.seen.count }
    public var auditHead: Data { audit.head }
    public func auditSnapshot() -> AuditSnapshot { audit.snapshot }

    /// Verifies a snapshot — this broker's own, or one exported earlier and
    /// read back from storage.
    public func verify(_ snapshot: AuditSnapshot) -> AuditVerification {
        AuditLog.verify(snapshot, key: keys.audit)
    }

    // MARK: Helpers

    /// Nil if `token` could still be presented right now; otherwise why not.
    private func problem(with token: CapabilityToken, at now: Date) -> String? {
        guard Digest.verifyMAC(token.mac, for: token.signingInput, key: keys.token) else { return "MAC invalid" }
        guard now < token.expiresAt else { return "expired" }
        return revocation.reason(for: token).map { "revoked (\($0))" }
    }

    private func grantDigest(_ request: DelegationRequest, thumbprint: String) -> String {
        var e = CanonicalEncoder()
        e.append("agent-authority/step-up/v1")
        e.append(request.subject)
        e.append(request.agent.id)
        e.append(request.agent.kind.rawValue)
        e.append(request.audience)
        e.append(request.scopes)
        e.append(thumbprint)
        e.append(request.parent?.id ?? "")
        return Digest.sha256Hex(e.bytes)
    }

    private func names(_ scopes: Set<Scope>) -> String {
        scopes.sorted().map(\.name).joined(separator: ",")
    }

    private func record(_ kind: AuditEvent.Kind, agent: String, subject: String, _ detail: String) {
        audit.append(AuditEvent(kind: kind, agentID: agent, subject: subject, detail: detail), at: clock.now())
    }
}
