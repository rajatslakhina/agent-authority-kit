import Foundation
import XCTest
import AgentAuthority
@testable import AgentAuthorityUI

@MainActor
final class AuthorityConsoleModelTests: XCTestCase {
    private func makeModel(clock: ManualClock = ManualClock()) throws -> AuthorityConsoleModel {
        try AuthorityConsoleModel(clock: clock, jobStepInterval: .milliseconds(2))
    }

    private func waitUntil(_ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
        for _ in 0..<3000 {
            if condition() { return }
            try? await Task.sleep(for: .milliseconds(1))
        }
        XCTFail("condition never became true", file: file, line: line)
    }

    func testApprovedConsentMintsAndThePaymentGoesThrough() async throws {
        let model = try makeModel()
        let request = Task { await model.request([Ledger.initiatePayment], for: Ledger.siri) }
        await waitUntil { model.pendingConsent != nil }
        XCTAssertEqual(model.pendingConsent?.challenge.scopes, [Ledger.initiatePayment])
        XCTAssertNil(model.credential(for: Ledger.siri.id), "nothing may be minted before the user answers")
        model.resolveConsent(approved: true)
        await request.value
        XCTAssertNil(model.pendingConsent)
        XCTAssertNotNil(model.credential(for: Ledger.siri.id))
        let paid = await model.invoke(Ledger.pay, as: Ledger.siri)
        XCTAssertTrue(paid)
    }

    func testDeclinedConsentMintsNothing() async throws {
        let model = try makeModel()
        let request = Task { await model.request([Ledger.exportData], for: Ledger.siri) }
        await waitUntil { model.pendingConsent != nil }
        model.resolveConsent(approved: false)
        await request.value
        XCTAssertNil(model.credential(for: Ledger.siri.id))
        XCTAssertEqual(model.activity.last?.allowed, false)
    }

    func testSecondConcurrentConsentIsDeclinedNotQueued() async throws {
        let model = try makeModel()
        let first = Task { await model.request([Ledger.initiatePayment], for: Ledger.siri) }
        await waitUntil { model.pendingConsent != nil }
        let firstChallenge = model.pendingConsent?.challenge.id
        await model.request([Ledger.initiatePayment], for: Ledger.budgetModel)
        XCTAssertNil(model.credential(for: Ledger.budgetModel.id))
        XCTAssertEqual(model.pendingConsent?.challenge.id, firstChallenge, "the open prompt must be untouched")
        model.resolveConsent(approved: true)
        await first.value
        XCTAssertNotNil(model.credential(for: Ledger.siri.id))
    }

    func testResolvingTwiceResumesTheRequestExactlyOnce() async throws {
        let model = try makeModel()
        model.resolveConsent(approved: true) // nothing open: must be a no-op
        let request = Task { await model.request([Ledger.initiatePayment], for: Ledger.siri) }
        await waitUntil { model.pendingConsent != nil }
        model.resolveConsent(approved: true)
        model.resolveConsent(approved: false) // second answer must not resume again or flip the first
        await request.value
        XCTAssertNil(model.pendingConsent)
        XCTAssertEqual(model.credential(for: Ledger.siri.id)?.token.scopes, [Ledger.initiatePayment])
        XCTAssertEqual(model.activity.filter { $0.text.hasPrefix("token issued") }.count, 1)
    }

    func testGrantsAccumulateIntoOneToken() async throws {
        let model = try makeModel()
        await model.request([Ledger.readTransactions], for: Ledger.siri)
        let request = Task { await model.request([Ledger.initiatePayment], for: Ledger.siri) }
        await waitUntil { model.pendingConsent != nil }
        model.resolveConsent(approved: true)
        await request.value
        XCTAssertEqual(model.credential(for: Ledger.siri.id)?.token.scopes, [Ledger.readTransactions, Ledger.initiatePayment])
    }

    func testRefusedGrantKeepsThePreviousToken() async throws {
        let model = try makeModel()
        await model.request([Ledger.readTransactions], for: Ledger.desktopMCP)
        let before = model.credential(for: Ledger.desktopMCP.id)?.token.id
        await model.request([Ledger.initiatePayment], for: Ledger.desktopMCP)
        XCTAssertNil(model.pendingConsent, "policy refusal must not prompt")
        XCTAssertEqual(model.credential(for: Ledger.desktopMCP.id)?.token.id, before)
    }

    func testDelegationProvesPossessionAndAttenuates() async throws {
        let model = try makeModel()
        await model.request([Ledger.readTransactions, Ledger.categorize], for: Ledger.siri)
        await model.delegate([Ledger.readTransactions], from: Ledger.siri, to: Ledger.budgetModel)
        let child = model.credential(for: Ledger.budgetModel.id)?.token
        XCTAssertEqual(child?.actorChain, [Ledger.siri.id, Ledger.budgetModel.id])
        XCTAssertEqual(child?.scopes, [Ledger.readTransactions])
    }

    func testCancelledJobCannotOverwriteTheNextOne() async throws {
        let model = try makeModel()
        await model.request([Ledger.readTransactions], for: Ledger.siri)
        model.startJob(as: Ledger.siri, steps: 3)
        await waitUntil {
            if case .running(let step, _) = model.job { return step >= 1 }
            return false
        }
        model.cancelJob()
        guard case .stopped(_, let reason) = model.job else { return XCTFail("cancel did not stop the job") }
        XCTAssertEqual(reason, "cancelled")
        // The next run reaches a terminal state immediately (the MCP client
        // holds no token), so any late write from the cancelled Siri run —
        // `.running(_, of: 3)` or `.finished(steps: 3)` — would replace it.
        model.startJob(as: Ledger.desktopMCP, steps: 5)
        await waitUntil {
            if case .stopped = model.job { return true }
            return false
        }
        XCTAssertEqual(model.job, .stopped(atStep: 1, reason: "no token"))
        try? await Task.sleep(for: .milliseconds(60))
        XCTAssertEqual(model.job, .stopped(atStep: 1, reason: "no token"), "the cancelled run wrote into the new run's state")
    }

    func testDismissingTheConsentSheetDeclines() async throws {
        let model = try makeModel()
        let request = Task { await model.request([Ledger.exportData], for: Ledger.siri) }
        await waitUntil { model.pendingConsent != nil }
        XCTAssertNotNil(model.consentSheetItem)
        model.consentSheetItem = nil
        await request.value
        XCTAssertNil(model.credential(for: Ledger.siri.id))
        model.consentSheetItem = nil // nothing open: no-op
        XCTAssertNil(model.pendingConsent)
    }

    func testRevokeAndKillSwitchMarkHoldersRevokedAndRegrantsStartClean() async throws {
        let clock = ManualClock()
        let model = try makeModel(clock: clock)
        await model.request([Ledger.readTransactions], for: Ledger.siri)
        await model.delegate([Ledger.readTransactions], from: Ledger.siri, to: Ledger.budgetModel)
        await model.request([Ledger.readTransactions], for: Ledger.desktopMCP)
        clock.advance(by: 1)
        await model.revoke(Ledger.siri)
        XCTAssertTrue(model.isRevoked(Ledger.siri.id))
        XCTAssertTrue(model.isRevoked(Ledger.budgetModel.id), "delegated through Siri, so it died too")
        XCTAssertFalse(model.isRevoked(Ledger.desktopMCP.id))
        let refused = await model.invoke(Ledger.listTransactions, as: Ledger.budgetModel)
        XCTAssertFalse(refused)

        await model.revokeAll()
        XCTAssertTrue(model.isRevoked(Ledger.desktopMCP.id))
        XCTAssertEqual(model.generation, 1)

        // A re-grant does not inherit the dead token's scopes.
        clock.advance(by: 1)
        await model.request([Ledger.categorize], for: Ledger.siri)
        XCTAssertFalse(model.isRevoked(Ledger.siri.id))
        XCTAssertEqual(model.credential(for: Ledger.siri.id)?.token.scopes, [Ledger.categorize])
    }

    func testRequestingHeldScopesIsANoop() async throws {
        let model = try makeModel()
        await model.request([Ledger.readTransactions], for: Ledger.siri)
        let id = model.credential(for: Ledger.siri.id)?.token.id
        await model.request([Ledger.readTransactions], for: Ledger.siri)
        XCTAssertEqual(model.credential(for: Ledger.siri.id)?.token.id, id)
    }

    func testRevocationStopsAnInFlightJobAtTheNextStep() async throws {
        let clock = ManualClock()
        let model = try makeModel(clock: clock)
        await model.request([Ledger.readTransactions], for: Ledger.budgetModel)
        model.startJob(as: Ledger.budgetModel, steps: 500)
        await waitUntil {
            if case .running(let step, _) = model.job { return step >= 3 }
            return false
        }
        clock.advance(by: 1)
        await model.revoke(Ledger.budgetModel)
        await waitUntil {
            if case .stopped = model.job { return true }
            return false
        }
        guard case .stopped(let step, let reason) = model.job else { return XCTFail("job did not stop") }
        XCTAssertLessThan(step, 500)
        XCTAssertTrue(reason.contains("revoked"), reason)
    }

    func testJobWithoutATokenStopsAtStepOneAndZeroStepsIsANoop() async throws {
        let model = try makeModel()
        model.startJob(as: Ledger.desktopMCP, steps: 0)
        XCTAssertEqual(model.job, .idle)
        model.startJob(as: Ledger.desktopMCP, steps: 3)
        await waitUntil {
            if case .stopped = model.job { return true }
            return false
        }
        guard case .stopped(let step, _) = model.job else { return XCTFail() }
        XCTAssertEqual(step, 1)
    }

    func testJobRunsToCompletionWhenNothingIsRevoked() async throws {
        let model = try makeModel()
        await model.request([Ledger.readTransactions], for: Ledger.siri)
        model.startJob(as: Ledger.siri, steps: 4)
        await waitUntil { model.job == .finished(steps: 4) }
    }

    func testSuiteRunsGreenAndAuditVerifiesThenTamperIsCaught() async throws {
        let model = try makeModel()
        await model.runSuite()
        XCTAssertEqual(model.suiteResults.count, AdversarialSuite.scenarioCount)
        XCTAssertEqual(model.suitePassCount, AdversarialSuite.scenarioCount)

        await model.tamperIfPossibleAfterActivity()
        XCTAssertEqual(model.auditStatus, .intact(count: model.auditEntries.count))
        guard case .broken = model.tamperStatus else { return XCTFail("tamper went unnoticed") }
    }

    func testTamperOnEmptyLogReportsNothingRatherThanCrashing() async throws {
        let model = try makeModel()
        await model.demonstrateTamper()
        XCTAssertNil(model.tamperStatus)
        XCTAssertEqual(model.activity.last?.text, "audit log is empty — nothing to tamper with")
    }

    func testActivityLogIsBounded() async throws {
        let model = try makeModel()
        for _ in 0..<(AuthorityConsoleModel.activityLimit + 50) {
            _ = await model.invoke(Ledger.listTransactions, as: Ledger.desktopMCP)
        }
        XCTAssertEqual(model.activity.count, AuthorityConsoleModel.activityLimit)
    }

    func testModelIsReleasedDespiteTheBrokerToBridgeEdge() throws {
        weak var weakModel: AuthorityConsoleModel?
        do {
            let model = try makeModel()
            weakModel = model
        }
        XCTAssertNil(weakModel, "model → broker → bridge → model must not be a cycle")
    }
}

extension AuthorityConsoleModel {
    /// Generate some audit history, then run the tamper demonstration.
    func tamperIfPossibleAfterActivity() async {
        await request([Ledger.readTransactions], for: Ledger.siri)
        _ = await invoke(Ledger.listTransactions, as: Ledger.siri)
        await demonstrateTamper()
    }
}
