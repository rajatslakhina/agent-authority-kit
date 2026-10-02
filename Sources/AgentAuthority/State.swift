import Foundation

// MARK: - Revocation

/// Revocation state. A value type owned by the broker actor, so every check and
/// every mutation is serialized with token minting.
///
/// Bounded memory without un-revoking: an entry may only be forgotten once no
/// token it could match can still be alive. Every token's lifetime is capped
/// at `hardMaxLifetime`. A token or grant entry recorded at `t` can only match
/// tokens minted before `t` (nothing is sub-delegated from a revoked grant), and
/// an agent entry at `t` only matches tokens issued at or before `t` — so every
/// entry is dead weight after `t + hardMaxLifetime`. If the table is full of entries
/// that are *not* yet prunable, the broker bumps the generation — revoking
/// everything — instead of dropping one. Failing closed costs every agent a
/// re-grant; failing open would silently resurrect a revoked token.
struct RevocationState: Sendable {
    private(set) var generation: UInt64
    private(set) var sealed = false
    private(set) var tokens: [String: Date] = [:]
    private(set) var grants: [String: Date] = [:]
    private(set) var agents: [String: Date] = [:]
    let capacity: Int
    let retention: TimeInterval

    init(capacity: Int, retention: TimeInterval, generation: UInt64 = 0) {
        self.capacity = capacity
        self.retention = retention
        self.generation = generation
    }

    var entryCount: Int { tokens.count + grants.count + agents.count }

    /// Why `token` is revoked, or nil if it is not.
    func reason(for token: CapabilityToken) -> String? {
        if sealed { return "broker sealed" }
        if token.generation < generation { return "revoke-all (generation \(generation))" }
        if tokens[token.id] != nil { return "token \(token.id.prefix(8))" }
        for ancestor in token.ancestorTokenIDs where tokens[ancestor] != nil {
            return "ancestor token \(ancestor.prefix(8))"
        }
        if grants[token.grantID] != nil { return "grant \(token.grantID.prefix(8))" }
        // Any agent anywhere in the act chain: revoking a delegator kills every
        // token delegated downstream of it.
        for actor in token.actorChain {
            if let at = agents[actor], token.issuedAt <= at { return "agent \(actor)" }
        }
        return nil
    }

    /// Everything about revocation that could affect a grant to these actors.
    /// Captured before the broker suspends for step-up and compared after: any
    /// difference means a revocation landed mid-consent.
    struct Witness: Equatable {
        let generation: UInt64
        let sealed: Bool
        let actorInstants: [Date?]
        let grantRevoked: Bool
        let parentTokenRevoked: Bool
    }

    func witness(actors: [String], grantID: String?, parentTokenID: String?) -> Witness {
        Witness(
            generation: generation,
            sealed: sealed,
            actorInstants: actors.map { agents[$0] },
            grantRevoked: grantID.map { grants[$0] != nil } ?? false,
            parentTokenRevoked: parentTokenID.map { tokens[$0] != nil } ?? false
        )
    }

    enum InsertOutcome: Equatable { case recorded, revokedAllAtCapacity, sealed }

    @discardableResult
    mutating func revokeToken(_ id: String, at now: Date) -> InsertOutcome { insert(\.tokens, id, now) }
    @discardableResult
    mutating func revokeGrant(_ id: String, at now: Date) -> InsertOutcome { insert(\.grants, id, now) }
    @discardableResult
    mutating func revokeAgent(_ id: String, at now: Date) -> InsertOutcome { insert(\.agents, id, now) }

    /// Returns false if the generation counter is exhausted; the state is then
    /// sealed and every token is refused from here on.
    @discardableResult
    mutating func revokeAll() -> Bool {
        if generation == .max {
            sealed = true
            return false
        }
        generation = generation.saturatingIncrement
        // Everything minted so far is dead by generation; the tables are moot.
        tokens.removeAll()
        grants.removeAll()
        agents.removeAll()
        return true
    }

    private mutating func insert(_ table: WritableKeyPath<RevocationState, [String: Date]>, _ key: String, _ now: Date) -> InsertOutcome {
        // Re-revoking moves the instant forward (later tokens die too).
        if self[keyPath: table][key] != nil {
            self[keyPath: table][key] = now
            return .recorded
        }
        if entryCount >= capacity { prune(now: now) }
        var outcome = InsertOutcome.recorded
        if entryCount >= capacity {
            // Cannot forget anything safely: fail closed.
            revokeAll()
            if sealed { return .sealed }
            outcome = .revokedAllAtCapacity
        }
        self[keyPath: table][key] = now
        return outcome
    }

    mutating func prune(now: Date) {
        let retention = self.retention
        let alive: (Date) -> Bool = { now.timeIntervalSince($0) < retention }
        tokens = tokens.filter { alive($0.value) }
        grants = grants.filter { alive($0.value) }
        agents = agents.filter { alive($0.value) }
    }
}

// MARK: - Replay cache

/// Remembers DPoP proof ids for as long as the proof could still pass the
/// freshness check. Bounded: when full of still-fresh ids it refuses new proofs
/// (fail closed) rather than evicting one, because evicting a live id would
/// make that exact proof replayable.
struct ReplayCache: Sendable {
    private(set) var seen: [String: Date] = [:]
    let capacity: Int

    init(capacity: Int) { self.capacity = capacity }

    enum Outcome: Equatable { case fresh, replayed, saturated }

    mutating func insert(_ id: String, expiresAt: Date, now: Date) -> Outcome {
        if let exp = seen[id], exp >= now { return .replayed }
        if seen.count >= capacity {
            seen = seen.filter { $0.value >= now }
        }
        if seen.count >= capacity { return .saturated }
        seen[id] = expiresAt
        return .fresh
    }
}

// MARK: - Audit log

public struct AuditEvent: Sendable, Hashable, Codable {
    public enum Kind: String, Sendable, Hashable, Codable {
        case issued, delegated, denied, authorized, stepUp, revoked
    }
    public let kind: Kind
    public let agentID: String
    public let subject: String
    public let detail: String

    public init(kind: Kind, agentID: String, subject: String, detail: String) {
        self.kind = kind
        self.agentID = agentID
        self.subject = subject
        self.detail = detail
    }
}

public struct AuditEntry: Sendable, Hashable, Codable, Identifiable {
    public let sequence: UInt64
    public let timestamp: Date
    public let event: AuditEvent
    public let previousMAC: Data
    public let mac: Data
    public var id: UInt64 { sequence }

    /// Copy with a different event but the original MACs — models an attacker
    /// with write access to storage but not the key.
    public func tampered(detail: String) -> AuditEntry {
        AuditEntry(
            sequence: sequence, timestamp: timestamp,
            event: AuditEvent(kind: event.kind, agentID: event.agentID, subject: event.subject, detail: detail),
            previousMAC: previousMAC, mac: mac
        )
    }

    static func signingInput(sequence: UInt64, timestamp: Date, event: AuditEvent, previousMAC: Data) -> Data {
        var e = CanonicalEncoder()
        e.append("agent-authority/audit/v1")
        e.append(sequence)
        e.append(timestamp)
        e.append(event.kind.rawValue)
        e.append(event.agentID)
        e.append(event.subject)
        e.append(event.detail)
        e.append(previousMAC)
        return e.bytes
    }
}

/// What a reader can export and verify: the retained window plus the anchor
/// (the MAC of the last entry that was rolled off).
///
/// Neither `anchor` nor `droppedCount` is itself authenticated: someone who can
/// rewrite storage can drop entries from the *front* and re-anchor on the new
/// first entry's `previousMAC`, just as they can truncate the tail. Both are
/// detected only by comparing against an exported head/anchor kept elsewhere.
public struct AuditSnapshot: Sendable, Hashable, Codable {
    public var entries: [AuditEntry]
    public let anchor: Data
    public let droppedCount: UInt64

    public init(entries: [AuditEntry], anchor: Data, droppedCount: UInt64) {
        self.entries = entries
        self.anchor = anchor
        self.droppedCount = droppedCount
    }
}

public enum AuditVerification: Sendable, Equatable {
    case intact(count: Int)
    /// Index into the snapshot's entries of the first entry that fails.
    case broken(index: Int)
}

/// A keyed hash chain: each entry's MAC covers its content *and* the previous
/// entry's MAC. Editing, reordering or deleting from the middle breaks every
/// MAC from that point on. Keyed (HMAC), not a bare hash, because a bare hash
/// chain can be recomputed end-to-end by anyone who can write the file.
///
/// Limits, stated: a chain cannot detect truncation of its own tail. Detecting
/// that needs an external anchor — export `head` to a server or to the user
/// periodically. Memory is bounded by rolling the oldest entries off and
/// keeping their last MAC as the new anchor.
struct AuditLog: Sendable {
    static let genesis = Data(repeating: 0, count: 32)

    private(set) var entries: [AuditEntry] = []
    private(set) var anchor: Data = AuditLog.genesis
    private(set) var droppedCount: UInt64 = 0
    private var nextSequence: UInt64 = 0
    let capacity: Int
    let key: Data

    init(capacity: Int, key: Data) {
        self.capacity = capacity
        self.key = key
    }

    var head: Data { entries.last?.mac ?? anchor }

    mutating func append(_ event: AuditEvent, at date: Date) {
        let previous = head
        let input = AuditEntry.signingInput(sequence: nextSequence, timestamp: date, event: event, previousMAC: previous)
        let entry = AuditEntry(sequence: nextSequence, timestamp: date, event: event, previousMAC: previous, mac: Digest.mac(input, key: key))
        nextSequence = nextSequence.saturatingIncrement
        entries.append(entry)
        while entries.count > capacity, let first = entries.first {
            anchor = first.mac
            droppedCount = droppedCount.saturatingIncrement
            entries.removeFirst()
        }
    }

    var snapshot: AuditSnapshot { AuditSnapshot(entries: entries, anchor: anchor, droppedCount: droppedCount) }

    static func verify(_ snapshot: AuditSnapshot, key: Data) -> AuditVerification {
        var previous = snapshot.anchor
        for (index, entry) in snapshot.entries.enumerated() {
            guard entry.previousMAC == previous else { return .broken(index: index) }
            let input = AuditEntry.signingInput(sequence: entry.sequence, timestamp: entry.timestamp, event: entry.event, previousMAC: entry.previousMAC)
            guard Digest.verifyMAC(entry.mac, for: input, key: key) else { return .broken(index: index) }
            previous = entry.mac
        }
        return .intact(count: snapshot.entries.count)
    }
}
