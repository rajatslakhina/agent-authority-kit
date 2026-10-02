import Foundation
import XCTest
@testable import AgentAuthority

final class PresentationTests: XCTestCase {
    func testProofSignedByAnotherKeyUnderTheRightPublicKeyIsRejected() async throws {
        let h = try Harness()
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let attacker = SoftwareProofKey()
        let attackerProof = try DPoPProof.make(for: c.token, method: "GET", target: Ledger.listTransactions.target, key: attacker, at: h.clock.now())
        // Splice the victim's public key in so the thumbprint check passes; the
        // signature still came from the attacker's key.
        let spliced = DPoPProof(
            id: attackerProof.id, method: attackerProof.method, target: attackerProof.target,
            issuedAt: attackerProof.issuedAt, tokenHash: attackerProof.tokenHash,
            publicKey: c.key.publicKey, signature: attackerProof.signature
        )
        await XCTAssertThrowsCode("proofSignatureInvalid") {
            try await h.broker.authorize(Presentation(token: c.token, proof: spliced), for: Ledger.listTransactions)
        }
    }

    func testProofForOneTokenCannotCarryAnother() async throws {
        let h = try Harness()
        let key = SoftwareProofKey()
        let a = try await h.issue(Ledger.siri, [Ledger.readTransactions], key: key)
        let b = try await h.issue(Ledger.siri, [Ledger.readTransactions], key: key)
        let proofForA = try a.present(for: Ledger.listTransactions, at: h.clock.now()).proof
        await XCTAssertThrowsCode("proofTokenBindingMismatch") {
            try await h.broker.authorize(Presentation(token: b.token, proof: proofForA), for: Ledger.listTransactions)
        }
    }

    func testProofFreshnessWindowAndSkew() async throws {
        let h = try Harness()
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let now = h.clock.now()
        await XCTAssertThrowsCode("proofStale") { try await h.call(c, Ledger.listTransactions, at: now.addingTimeInterval(-61)) }
        await XCTAssertThrowsCode("proofStale") { try await h.call(c, Ledger.listTransactions, at: now.addingTimeInterval(6)) }
        _ = try await h.call(c, Ledger.listTransactions, at: now.addingTimeInterval(4))
        _ = try await h.call(c, Ledger.listTransactions, at: now.addingTimeInterval(-60))
    }

    /// At age == proofWindow the proof is still fresh, so its id must still be
    /// remembered. An off-by-one (`>` instead of `>=`) in the cache makes the
    /// exact same proof replayable at that instant.
    func testReplayIsCaughtAtTheExactWindowBoundary() async throws {
        let h = try Harness()
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let p = try c.present(for: Ledger.listTransactions, at: h.clock.now())
        _ = try await h.broker.authorize(p, for: Ledger.listTransactions)
        h.clock.advance(by: 60)
        await XCTAssertThrowsCode("proofReplayed") { try await h.broker.authorize(p, for: Ledger.listTransactions) }
        h.clock.advance(by: 0.5)
        await XCTAssertThrowsCode("proofStale") { try await h.broker.authorize(p, for: Ledger.listTransactions) }
    }

    func testReplayCacheFailsClosedWhenFullThenRecovers() async throws {
        var config = BrokerConfiguration()
        config.replayCacheCapacity = 2
        let h = try Harness(configuration: config)
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        try await h.call(c, Ledger.listTransactions)
        try await h.call(c, Ledger.listTransactions)
        await XCTAssertThrowsCode("replayCacheSaturated") { try await h.call(c, Ledger.listTransactions) }
        let count = await h.broker.replayCacheCount
        XCTAssertEqual(count, 2)
        h.clock.advance(by: 61)
        try await h.call(c, Ledger.listTransactions)
        let after = await h.broker.replayCacheCount
        XCTAssertEqual(after, 1)
    }

    func testTamperedTokenFailsTheMAC() async throws {
        let h = try Harness()
        let c = try await h.issue(Ledger.desktopMCP, [Ledger.readTransactions])
        let forged = AgentCredential(token: c.token.tampered(scopes: [Ledger.readTransactions]), key: c.key)
        // Same scopes: the MAC still verifies — proves the check is on content, not identity.
        try await h.call(forged, Ledger.listTransactions)
        let widened = AgentCredential(token: c.token.tampered(scopes: [Ledger.readTransactions, Ledger.exportData]), key: c.key)
        await XCTAssertThrowsCode("tokenSignatureInvalid") { try await h.call(widened, Ledger.export) }
    }

    func testTokenFromAnotherBrokerIsRejected() async throws {
        let a = try Harness()
        let b = try Harness(clock: a.clock)
        let c = try await a.issue(Ledger.siri, [Ledger.readTransactions])
        await XCTAssertThrowsCode("tokenSignatureInvalid") {
            try await b.broker.authorize(try c.present(for: Ledger.listTransactions, at: a.clock.now()), for: Ledger.listTransactions)
        }
    }

    func testExpiryBoundaryIsExclusive() async throws {
        let h = try Harness()
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions], lifetime: 30)
        h.clock.advance(by: 29.999)
        try await h.call(c, Ledger.listTransactions)
        h.clock.advance(by: 0.001)
        await XCTAssertThrowsCode("tokenExpired") { try await h.call(c, Ledger.listTransactions) }
    }

    func testAuthorizationCarriesTheActChain() async throws {
        let h = try Harness()
        let parent = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let child = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], parent: parent)
        let auth = try await h.call(child, Ledger.listTransactions)
        XCTAssertEqual(auth.actorChain, ["siri-intent", "budget-model"])
        XCTAssertEqual(auth.agentID, "budget-model")
        XCTAssertEqual(auth.subject, Ledger.subject)
    }
}

final class RevocationTests: XCTestCase {
    func testRevokingAGrantKillsTheWholeTree() async throws {
        let h = try Harness()
        let root = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let child = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], parent: root)
        let unrelated = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        await h.broker.revokeGrant(root.token.grantID)
        await XCTAssertThrowsCode("revoked") { try await h.call(root, Ledger.listTransactions) }
        await XCTAssertThrowsCode("revoked") { try await h.call(child, Ledger.listTransactions) }
        try await h.call(unrelated, Ledger.listTransactions)
        // And no new delegation from the revoked grant.
        await XCTAssertThrowsCode("parentInvalid") {
            try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], parent: root)
        }
    }

    func testRevokingOneTokenLeavesSiblings() async throws {
        let h = try Harness()
        let a = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let b = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        await h.broker.revokeToken(a.token.id)
        await XCTAssertThrowsCode("revoked") { try await h.call(a, Ledger.listTransactions) }
        try await h.call(b, Ledger.listTransactions)
    }

    func testAgentRevocationIsAnInstantNotABan() async throws {
        let h = try Harness()
        let before = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions])
        await h.broker.revokeAgent(Ledger.budgetModel.id)
        h.clock.advance(by: 1)
        let after = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions])
        await XCTAssertThrowsCode("revoked") { try await h.call(before, Ledger.listTransactions) }
        try await h.call(after, Ledger.listTransactions)
    }

    /// The table is bounded, and when it is full of entries that are still
    /// load-bearing it revokes everything rather than forget one.
    func testFullRevocationTableFailsClosed() async throws {
        var config = BrokerConfiguration()
        config.revocationCapacity = 2
        let h = try Harness(configuration: config)
        let bystander = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let tokens = [try await h.issue(Ledger.siri, [Ledger.readTransactions]),
                      try await h.issue(Ledger.siri, [Ledger.readTransactions]),
                      try await h.issue(Ledger.siri, [Ledger.readTransactions])]
        for t in tokens.prefix(2) { await h.broker.revokeToken(t.token.id) }
        let generationBefore = await h.broker.generation
        try await h.call(bystander, Ledger.listTransactions)

        await h.broker.revokeToken(tokens[2].token.id)
        let generationAfter = await h.broker.generation
        XCTAssertEqual(generationAfter, generationBefore + 1)
        for t in tokens {
            await XCTAssertThrowsCode("revoked") { try await h.call(t, Ledger.listTransactions) }
        }
        await XCTAssertThrowsCode("revoked") { try await h.call(bystander, Ledger.listTransactions) }
    }

    func testExpiredRevocationsArePrunedInsteadOfRevokingEverything() async throws {
        var config = BrokerConfiguration()
        config.revocationCapacity = 2
        let h = try Harness(configuration: config)
        await h.broker.revokeToken("old-1")
        await h.broker.revokeToken("old-2")
        h.clock.advance(by: config.hardMaxLifetime)
        let fresh = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        await h.broker.revokeToken("new-1")
        let generation = await h.broker.generation
        let entries = await h.broker.revocationEntryCount
        XCTAssertEqual(generation, 0)
        XCTAssertEqual(entries, 1)
        try await h.call(fresh, Ledger.listTransactions)
    }

    func testGenerationExhaustionSealsTheBroker() async throws {
        let clock = ManualClock()
        let broker = try AuthorityBroker(
            policy: Ledger.referencePolicy, stepUp: FixedStepUpAuthenticator(approving: true, clock: clock),
            clock: clock, configuration: BrokerConfiguration(), keys: .random(), initialGeneration: .max - 1
        )
        let h = Harness(broker: broker, clock: clock)
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        await broker.revokeAll()
        let atMax = await broker.generation
        XCTAssertEqual(atMax, .max)
        let afterMax = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        try await h.call(afterMax, Ledger.listTransactions)

        await broker.revokeAll()
        let sealed = await broker.isSealed
        XCTAssertTrue(sealed)
        await XCTAssertThrowsCode("brokerSealed") { try await h.call(afterMax, Ledger.listTransactions) }
        await XCTAssertThrowsCode("brokerSealed") { try await h.issue(Ledger.siri, [Ledger.readTransactions]) }
        await XCTAssertThrowsCode("brokerSealed") { try await h.call(c, Ledger.listTransactions) }
    }

    /// Parks N sensitive exchanges inside consent, revokes everything while
    /// they are suspended, then lets them resume. Every one of them must be
    /// refused with `revokedDuringStepUp`: none may mint with the new
    /// generation on the strength of a pre-suspension check.
    func testRevokeAllWhileManyExchangesAreSuspendedInConsent() async throws {
        let gate = MultiGate()
        let h = try Harness(stepUp: { clock in
            ScriptedStepUp { c in
                await gate.wait()
                return .answering(c, approved: true, at: clock.now(), method: "t")
            }
        })
        let n = 12
        let tasks = (0..<n).map { _ in Task { try await h.issue(Ledger.siri, [Ledger.initiatePayment]) } }
        for _ in 0..<5000 {
            if await gate.waitingCount == n { break }
            await Task.yield()
        }
        let parked = await gate.waitingCount
        XCTAssertEqual(parked, n)
        await h.broker.revokeAll()
        await gate.open()
        for task in tasks {
            await XCTAssertThrowsCode("revokedDuringStepUp") { try await task.value }
        }
        // And exchanges that start after the revocation succeed normally.
        let fresh = try await h.issue(Ledger.siri, [Ledger.initiatePayment])
        try await h.call(fresh, Ledger.pay)
    }

    func testRevokingADelegatorsTokenReachesEveryDescendant() async throws {
        let h = try Harness(policy: LaxPolicy())
        let root = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let child = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], parent: root)
        let grandchild = try await h.issue(AgentPrincipal(id: "helper", kind: .onDeviceModel, displayName: "h"), [Ledger.readTransactions], parent: child)
        let sibling = try await h.issue(Ledger.desktopMCP, [Ledger.readTransactions], parent: root)
        XCTAssertEqual(grandchild.token.ancestorTokenIDs, [root.token.id, child.token.id])
        await h.broker.revokeToken(child.token.id)
        await XCTAssertThrowsCode("revoked") { try await h.call(child, Ledger.listTransactions) }
        await XCTAssertThrowsCode("revoked") { try await h.call(grandchild, Ledger.listTransactions) }
        try await h.call(root, Ledger.listTransactions)
        try await h.call(sibling, Ledger.listTransactions)
    }

    func testCapacityFallbackIsWrittenToTheAuditLog() async throws {
        var config = BrokerConfiguration()
        config.revocationCapacity = 1
        let h = try Harness(configuration: config)
        await h.broker.revokeToken("a")
        await h.broker.revokeToken("b")
        let details = await h.broker.auditSnapshot().entries.map(\.event.detail)
        XCTAssertTrue(details.contains { $0.hasPrefix("all (revocation table full") }, "\(details)")
    }
}

final class AuditTests: XCTestCase {
    private func populated() async throws -> Harness {
        let h = try Harness()
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions, Ledger.initiatePayment])
        try await h.call(c, Ledger.listTransactions)
        try await h.call(c, Ledger.pay)
        _ = try? await h.issue(Ledger.desktopMCP, [Ledger.exportData])
        await h.broker.revokeAgent(Ledger.siri.id)
        return h
    }

    func testChainIsIntactAndRecordsTheStory() async throws {
        let h = try await populated()
        let snapshot = await h.broker.auditSnapshot()
        let verdict = await h.broker.verify(snapshot)
        XCTAssertEqual(verdict, .intact(count: snapshot.entries.count))
        XCTAssertEqual(snapshot.entries.map(\.event.kind), [.stepUp, .issued, .authorized, .authorized, .denied, .revoked])
        XCTAssertEqual(snapshot.entries.map(\.sequence), Array(0..<6).map(UInt64.init))
    }

    func testEditingAnEntryIsDetectedAtThatEntry() async throws {
        let h = try await populated()
        var snapshot = await h.broker.auditSnapshot()
        snapshot.entries[3] = snapshot.entries[3].tampered(detail: "nothing happened")
        let verdict = await h.broker.verify(snapshot)
        XCTAssertEqual(verdict, .broken(index: 3))
    }

    func testDeletingAndReorderingAreDetected() async throws {
        let h = try await populated()
        var deleted = await h.broker.auditSnapshot()
        deleted.entries.remove(at: 2)
        let v1 = await h.broker.verify(deleted)
        XCTAssertEqual(v1, .broken(index: 2))

        var swapped = await h.broker.auditSnapshot()
        swapped.entries.swapAt(1, 2)
        let v2 = await h.broker.verify(swapped)
        XCTAssertEqual(v2, .broken(index: 1))
    }

    /// Why keyed: an attacker who rewrites an entry and recomputes the chain
    /// with *their own* key produces a chain a bare-hash verifier would accept.
    func testRecomputingTheChainWithoutTheKeyIsDetected() async throws {
        let h = try await populated()
        var snapshot = await h.broker.auditSnapshot()
        let wrongKey = Digest.randomKey()
        var previous = snapshot.anchor
        for i in snapshot.entries.indices {
            let e = snapshot.entries[i]
            let event = i == 2 ? AuditEvent(kind: e.event.kind, agentID: e.event.agentID, subject: e.event.subject, detail: "rewritten") : e.event
            let input = AuditEntry.signingInput(sequence: e.sequence, timestamp: e.timestamp, event: event, previousMAC: previous)
            let mac = Digest.mac(input, key: wrongKey)
            snapshot.entries[i] = AuditEntry(sequence: e.sequence, timestamp: e.timestamp, event: event, previousMAC: previous, mac: mac)
            previous = mac
        }
        // Internally consistent under the attacker's key...
        XCTAssertEqual(AuditLog.verify(snapshot, key: wrongKey), .intact(count: snapshot.entries.count))
        // ...and rejected under the broker's.
        let verdict = await h.broker.verify(snapshot)
        XCTAssertEqual(verdict, .broken(index: 0))
    }

    func testBoundedLogRollsTheAnchorAndStillVerifies() async throws {
        var config = BrokerConfiguration()
        config.auditCapacity = 4
        let h = try Harness(configuration: config)
        for i in 0..<10 { await h.broker.revokeToken("t\(i)") }
        let snapshot = await h.broker.auditSnapshot()
        XCTAssertEqual(snapshot.entries.count, 4)
        XCTAssertEqual(snapshot.droppedCount, 6)
        XCTAssertEqual(snapshot.entries.first?.sequence, 6)
        XCTAssertNotEqual(snapshot.anchor, AuditLog.genesis)
        let verdict = await h.broker.verify(snapshot)
        XCTAssertEqual(verdict, .intact(count: 4))

        let forgedAnchor = AuditSnapshot(entries: snapshot.entries, anchor: AuditLog.genesis, droppedCount: 0)
        let v2 = await h.broker.verify(forgedAnchor)
        XCTAssertEqual(v2, .broken(index: 0))
    }
}

final class PrimitiveTests: XCTestCase {
    func testCanonicalEncodingIsUnambiguous() {
        var a = CanonicalEncoder(); a.append("ab"); a.append("c")
        var b = CanonicalEncoder(); b.append("a"); b.append("bc")
        XCTAssertNotEqual(a.bytes, b.bytes)
        var c = CanonicalEncoder(); c.append(["x", "y"])
        var d = CanonicalEncoder(); d.append(["xy"])
        XCTAssertNotEqual(c.bytes, d.bytes)
    }

    func testScopeEncodingIsOrderIndependentButTierSensitive() {
        var a = CanonicalEncoder(); a.append(Set([Ledger.readTransactions, Ledger.categorize]))
        var b = CanonicalEncoder(); b.append(Set([Ledger.categorize, Ledger.readTransactions]))
        XCTAssertEqual(a.bytes, b.bytes)
        var c = CanonicalEncoder(); c.append(Set([Scope("transactions.read", tier: .write)]))
        var d = CanonicalEncoder(); d.append(Set([Ledger.readTransactions]))
        XCTAssertNotEqual(c.bytes, d.bytes)
    }

    func testSaturatingIncrementAndClockGuards() {
        XCTAssertEqual(UInt64.max.saturatingIncrement, .max)
        XCTAssertEqual(UInt64(41).saturatingIncrement, 42)
        let clock = ManualClock()
        let start = clock.now()
        for bad in [TimeInterval.nan, .infinity, -1, 0] { clock.advance(by: bad) }
        XCTAssertEqual(clock.now(), start)
    }

    func testStaticPolicyDeniesUnknownKindsAndListsMissingScopes() {
        let policy = StaticAuthorityPolicy(rules: [:])
        let request = PolicyRequest(subject: "u", agent: Ledger.siri, audience: "a", scopes: [Ledger.readTransactions], chainLength: 1)
        guard case .deny = policy.evaluate(request) else { return XCTFail("expected deny") }
        let mcp = PolicyRequest(subject: "u", agent: Ledger.desktopMCP, audience: "a", scopes: [Ledger.readTransactions, Ledger.exportData], chainLength: 1)
        guard case .deny(let reason) = Ledger.referencePolicy.evaluate(mcp) else { return XCTFail("expected deny") }
        XCTAssertTrue(reason.contains("data.export"))
    }

    func testThumbprintIsStablePerKeyAndDistinctAcrossKeys() {
        let k1 = SoftwareProofKey(), k2 = SoftwareProofKey()
        XCTAssertEqual(k1.thumbprint.count, 64)
        XCTAssertNotEqual(k1.thumbprint, k2.thumbprint)
        XCTAssertEqual(k1.thumbprint, ProofVerifier.thumbprint(of: k1.publicKey))
    }
}
