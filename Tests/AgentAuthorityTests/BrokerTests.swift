import Foundation
import XCTest
@testable import AgentAuthority

final class AdversarialSuiteTests: XCTestCase {
    func testEveryScenarioIsStoppedForTheExpectedReason() async {
        let results = await AdversarialSuite.run()
        XCTAssertEqual(results.count, AdversarialSuite.scenarioCount)
        XCTAssertEqual(results.count, 20)
        for result in results where !result.passed {
            XCTFail("\(result.name): expected \(result.expectedDenial ?? "allowed"), observed \(result.observed)")
        }
    }

    /// The suite has teeth: against a policy that grants everything, the
    /// scenarios that depend on the policy must FAIL — while the ones the broker
    /// enforces on its own must still pass.
    func testSuiteFailsAgainstABrokenPolicy() async {
        let results = await AdversarialSuite.run(policy: LaxPolicy())
        XCTAssertEqual(results.count, AdversarialSuite.scenarioCount)
        // Exactly these two depend on the policy; every other scenario is held
        // by the broker's own invariants and must still pass.
        let policyDependent: Set<String> = ["Remote client asks to pay", "Delegation to a remote client"]
        for result in results {
            if policyDependent.contains(result.name) {
                XCTAssertFalse(result.passed, "\(result.name) should fail under a policy that grants everything")
                XCTAssertEqual(result.observed, .allowed, result.name)
            } else {
                XCTAssertTrue(result.passed, "\(result.name) must not depend on the policy (observed \(result.observed))")
            }
        }
        XCTAssertEqual(Set(results.filter { !$0.passed }.map(\.name)), policyDependent)
    }
}

final class ExchangeTests: XCTestCase {
    func testBrokerFloorDemandsConsentEvenWhenPolicyAsksForNone() async throws {
        let clock = ManualClock()
        let declining = CountingStepUp(approve: false, clock: clock)
        let h = try Harness(policy: LaxPolicy(), stepUp: { _ in declining }, clock: clock)
        await XCTAssertThrowsCode("stepUpDeclined") { try await h.issue(Ledger.desktopMCP, [Ledger.initiatePayment]) }
        XCTAssertEqual(declining.count, 1)

        // ...and does not prompt for scopes below the floor.
        _ = try await h.issue(Ledger.desktopMCP, [Ledger.readTransactions, Ledger.categorize])
        XCTAssertEqual(declining.count, 1)
    }

    func testMalformedPolicyDecisionsAreRejected() async throws {
        let bad: [PolicyDecision] = [
            .allow(maxLifetime: .nan, stepUp: [], maxChainLength: 1),
            .allow(maxLifetime: .infinity, stepUp: [], maxChainLength: 1),
            .allow(maxLifetime: -5, stepUp: [], maxChainLength: 1),
            .allow(maxLifetime: 60, stepUp: [Ledger.exportData], maxChainLength: 1),
        ]
        for decision in bad {
            let h = try Harness(policy: CannedPolicy(decision: decision))
            await XCTAssertThrowsCode("policyViolation") { try await h.issue(Ledger.siri, [Ledger.readTransactions]) }
        }
        let zeroChain = try Harness(policy: CannedPolicy(decision: .allow(maxLifetime: 60, stepUp: [], maxChainLength: 0)))
        await XCTAssertThrowsCode("delegationTooDeep") { try await zeroChain.issue(Ledger.siri, [Ledger.readTransactions]) }
    }

    func testLifetimeIsClampedToTheHardCeiling() async throws {
        let h = try Harness(policy: LaxPolicy())
        let c = try await h.issue(Ledger.siri, [Ledger.readTransactions], lifetime: 1e12)
        XCTAssertEqual(c.token.expiresAt.timeIntervalSince(c.token.issuedAt), 900, accuracy: 0.001)
    }

    func testPolicyLifetimeShortensTheRequest() async throws {
        let h = try Harness()
        let c = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], lifetime: 600)
        XCTAssertEqual(c.token.expiresAt.timeIntervalSince(c.token.issuedAt), 120, accuracy: 0.001)
    }

    func testChildNeverOutlivesParent() async throws {
        let h = try Harness()
        let parent = try await h.issue(Ledger.siri, [Ledger.readTransactions], lifetime: 60)
        h.clock.advance(by: 10)
        let child = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], parent: parent, lifetime: 120)
        XCTAssertEqual(child.token.expiresAt, parent.token.expiresAt)
        XCTAssertEqual(child.token.grantID, parent.token.grantID)
        XCTAssertEqual(child.token.actorChain, [Ledger.siri.id, Ledger.budgetModel.id])
    }

    func testDelegationCycleIsRejected() async throws {
        let h = try Harness(policy: LaxPolicy())
        let a = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let b = try await h.issue(Ledger.budgetModel, [Ledger.readTransactions], parent: a)
        await XCTAssertThrowsCode("invalidRequest") { try await h.issue(Ledger.siri, [Ledger.readTransactions], parent: b) }
    }

    func testHardChainCeilingHoldsAgainstAPermissivePolicy() async throws {
        let h = try Harness(policy: LaxPolicy())
        var parent = try await h.issue(AgentPrincipal(id: "a0", kind: .appIntent, displayName: "a0"), [Ledger.readTransactions])
        for i in 1..<3 {
            parent = try await h.issue(AgentPrincipal(id: "a\(i)", kind: .appIntent, displayName: "a\(i)"), [Ledger.readTransactions], parent: parent)
        }
        XCTAssertEqual(parent.token.actorChain.count, 3)
        await XCTAssertThrowsCode("delegationTooDeep") {
            try await h.issue(AgentPrincipal(id: "a3", kind: .appIntent, displayName: "a3"), [Ledger.readTransactions], parent: parent)
        }
    }

    func testSubDelegationMustKeepAudience() async throws {
        let h = try Harness(policy: LaxPolicy())
        let parent = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let key = SoftwareProofKey()
        await XCTAssertThrowsCode("invalidRequest") {
            try await h.broker.exchange(DelegationRequest(
                subject: Ledger.subject, agent: Ledger.budgetModel, audience: "messages",
                scopes: [Ledger.readTransactions], requestedLifetime: 60, proofKey: key.publicKey,
                parent: parent.token, parentProof: try parent.delegationProof(at: h.clock.now())
            ))
        }
    }

    func testInvalidRequestsAreRefused() async throws {
        let h = try Harness()
        for lifetime in [TimeInterval.nan, .infinity, -.infinity, 0, -1] {
            await XCTAssertThrowsCode("invalidRequest") { try await h.issue(Ledger.siri, [Ledger.readTransactions], lifetime: lifetime) }
        }
        await XCTAssertThrowsCode("invalidRequest") { try await h.issue(Ledger.siri, []) }
        await XCTAssertThrowsCode("invalidRequest") {
            try await h.broker.exchange(DelegationRequest(
                subject: Ledger.subject, agent: Ledger.siri, audience: Ledger.audience,
                scopes: [Ledger.readTransactions], requestedLifetime: 60, proofKey: Data([1, 2, 3])
            ))
        }
        await XCTAssertThrowsCode("invalidRequest") {
            try await h.broker.exchange(DelegationRequest(
                subject: "", agent: Ledger.siri, audience: Ledger.audience,
                scopes: [Ledger.readTransactions], requestedLifetime: 60, proofKey: SoftwareProofKey().publicKey
            ))
        }
    }

    func testForgedTierIsADifferentScope() async throws {
        let h = try Harness()
        // Siri's rule lists the real payments.initiate. A scope with the same
        // name but tier .read must not match it — under name-only equality it
        // would be granted, and below the consent floor at that.
        let clock = h.clock
        let counting = CountingStepUp(approve: true, clock: clock)
        let h2 = try Harness(stepUp: { _ in counting }, clock: clock)
        let disguised = Scope(Ledger.initiatePayment.name, tier: .read)
        await XCTAssertThrowsCode("policyDenied") { try await h2.issue(Ledger.siri, [disguised]) }
        XCTAssertEqual(counting.count, 0)
        _ = h
    }

    func testConfigurationAndKeysAreValidated() throws {
        var config = BrokerConfiguration()
        config.proofWindow = .nan
        XCTAssertThrowsError(try Harness(configuration: config))
        config = BrokerConfiguration()
        config.replayCacheCapacity = 0
        XCTAssertThrowsError(try Harness(configuration: config))
        config = BrokerConfiguration()
        config.clockSkew = -1
        XCTAssertThrowsError(try Harness(configuration: config))
        XCTAssertThrowsError(try BrokerKeys(token: Data(count: 8), audit: Data(count: 32)))
        XCTAssertNoThrow(try BrokerKeys(token: Data(count: 32), audit: Data(count: 32)))
    }
}

final class SubDelegationProofTests: XCTestCase {
    func testSubDelegationWithoutProofOfPossessionIsRefused() async throws {
        let h = try Harness()
        let parent = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        await XCTAssertThrowsExactly(.invalidRequest("sub-delegation requires proof of possession of the parent token")) {
            try await h.broker.exchange(DelegationRequest(
                subject: Ledger.subject, agent: Ledger.budgetModel, audience: Ledger.audience,
                scopes: [Ledger.readTransactions], requestedLifetime: 60,
                proofKey: SoftwareProofKey().publicKey, parent: parent.token
            ))
        }
    }

    func testParentProofIsSingleUseAndMustNameTheDelegationTarget() async throws {
        let h = try Harness()
        let parent = try await h.issue(Ledger.siri, [Ledger.readTransactions])
        let request = try parent.delegate([Ledger.readTransactions], to: Ledger.budgetModel, childKey: SoftwareProofKey(), lifetime: 60, at: h.clock.now())
        _ = try await h.broker.exchange(request)
        await XCTAssertThrowsCode("proofReplayed") { try await h.broker.exchange(request) }

        // A proof minted for an ordinary call cannot authorize a delegation.
        let callProof = try parent.present(for: Ledger.listTransactions, at: h.clock.now()).proof
        await XCTAssertThrowsCode("proofTargetMismatch") {
            try await h.broker.exchange(DelegationRequest(
                subject: Ledger.subject, agent: Ledger.budgetModel, audience: Ledger.audience,
                scopes: [Ledger.readTransactions], requestedLifetime: 60,
                proofKey: SoftwareProofKey().publicKey, parent: parent.token, parentProof: callProof
            ))
        }
    }
}

final class StepUpReentrancyTests: XCTestCase {
    func testRevokeAllDuringConsentAbortsTheMint() async throws {
        let ref = BrokerRef()
        let h = try Harness(stepUp: { clock in
            ScriptedStepUp { c in
                await ref.broker?.revokeAll()
                return .answering(c, approved: true, at: clock.now(), method: "t")
            }
        })
        ref.broker = h.broker
        await XCTAssertThrowsCode("revokedDuringStepUp") { try await h.issue(Ledger.siri, [Ledger.initiatePayment]) }
    }

    func testRevokingTheParentGrantDuringConsentAbortsTheChild() async throws {
        let clock = ManualClock()
        let ref = BrokerRef()
        let grantBox = GrantBox()
        let broker = try AuthorityBroker(policy: Ledger.referencePolicy, stepUp: ScriptedStepUp { c in
            if c.agent == Ledger.budgetModel, let grant = grantBox.value {
                await ref.broker?.revokeGrant(grant)
            }
            return .answering(c, approved: true, at: clock.now(), method: "t")
        }, clock: clock)
        ref.broker = broker
        let h = Harness(broker: broker, clock: clock)
        let root = try await h.issue(Ledger.siri, [Ledger.initiatePayment])
        grantBox.value = root.token.grantID
        await XCTAssertThrowsCode("revokedDuringStepUp") {
            try await h.issue(Ledger.budgetModel, [Ledger.initiatePayment], parent: root)
        }
    }

    func testRevokingTheParentTokenDuringConsentAbortsTheChild() async throws {
        let clock = ManualClock()
        let ref = BrokerRef()
        let box = GrantBox()
        let broker = try AuthorityBroker(policy: Ledger.referencePolicy, stepUp: ScriptedStepUp { c in
            if c.agent == Ledger.budgetModel, let id = box.value { await ref.broker?.revokeToken(id) }
            return .answering(c, approved: true, at: clock.now(), method: "t")
        }, clock: clock)
        ref.broker = broker
        let h = Harness(broker: broker, clock: clock)
        let root = try await h.issue(Ledger.siri, [Ledger.initiatePayment])
        box.value = root.token.id
        await XCTAssertThrowsCode("revokedDuringStepUp") {
            try await h.issue(Ledger.budgetModel, [Ledger.initiatePayment], parent: root)
        }
    }

    func testRevokingAnUnrelatedAgentDuringConsentDoesNotAbort() async throws {
        let ref = BrokerRef()
        let h = try Harness(stepUp: { clock in
            ScriptedStepUp { c in
                await ref.broker?.revokeAgent("someone-else")
                return .answering(c, approved: true, at: clock.now(), method: "t")
            }
        })
        ref.broker = h.broker
        let c = try await h.issue(Ledger.siri, [Ledger.initiatePayment])
        try await h.call(c, Ledger.pay)
    }

    func testParentExpiringDuringConsentAbortsTheChild() async throws {
        let h = try Harness(stepUp: { clock in
            ScriptedStepUp { c in
                let receipt = StepUpReceipt.answering(c, approved: true, at: clock.now(), method: "t")
                if c.agent == Ledger.budgetModel { clock.advance(by: 61) }
                return receipt
            }
        })
        let parent = try await h.issue(Ledger.siri, [Ledger.initiatePayment], lifetime: 60)
        // Exactly "expired": the post-suspension re-check, not the backstop.
        await XCTAssertThrowsExactly(.parentInvalid("expired")) {
            try await h.issue(Ledger.budgetModel, [Ledger.initiatePayment], parent: parent)
        }
    }

    func testCancellationWhileSuspendedInConsentMintsNothing() async throws {
        let gate = Gate()
        let h = try Harness(stepUp: { clock in
            ScriptedStepUp { c in
                await gate.wait()
                return .answering(c, approved: true, at: clock.now(), method: "t")
            }
        })
        let task = Task { try await h.issue(Ledger.siri, [Ledger.initiatePayment]) }
        for _ in 0..<2000 {
            if await gate.isWaiting { break }
            await Task.yield()
        }
        let suspended = await gate.isWaiting
        XCTAssertTrue(suspended)
        task.cancel()
        await gate.open()
        await XCTAssertThrowsCode("cancelled") { try await task.value }
    }

    func testReceiptTimestampedBeforeTheChallengeIsStale() async throws {
        let h = try Harness(stepUp: { _ in
            ScriptedStepUp { c in .answering(c, approved: true, at: c.issuedAt.addingTimeInterval(-1), method: "t") }
        })
        await XCTAssertThrowsCode("stepUpStale") { try await h.issue(Ledger.siri, [Ledger.exportData]) }
    }

    func testReceiptForAnotherChallengeIsRejected() async throws {
        let h = try Harness(stepUp: { clock in
            ScriptedStepUp { c in
                StepUpReceipt(challengeID: "old", grantDigest: c.grantDigest, approved: true, authenticatedAt: clock.now(), method: "t")
            }
        })
        await XCTAssertThrowsCode("stepUpMismatch") { try await h.issue(Ledger.siri, [Ledger.exportData]) }
    }
}

final class GrantBox: @unchecked Sendable {
    // @unchecked: written before the second exchange starts, read inside it.
    var value: String?
}

extension Harness {
    init(broker: AuthorityBroker, clock: ManualClock) {
        self.broker = broker
        self.clock = clock
    }
}
