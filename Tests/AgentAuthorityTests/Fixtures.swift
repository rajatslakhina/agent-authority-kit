import Foundation
import XCTest
@testable import AgentAuthority

/// Grants everything to everyone, asks for no step-up, allows long chains.
/// The deliberately broken policy the broker's own invariants must survive.
struct LaxPolicy: AuthorityPolicy {
    func evaluate(_ request: PolicyRequest) -> PolicyDecision {
        .allow(maxLifetime: 1_000_000_000, stepUp: [], maxChainLength: 10)
    }
}

/// Returns whatever decision it was built with — for malformed-policy tests.
struct CannedPolicy: AuthorityPolicy {
    let decision: PolicyDecision
    func evaluate(_ request: PolicyRequest) -> PolicyDecision { decision }
}

/// Counts how many times the user was asked.
final class CountingStepUp: StepUpAuthenticator, @unchecked Sendable {
    // @unchecked: `count` is only touched under `lock`.
    private let lock = NSLock()
    private var _count = 0
    let approve: Bool
    let clock: any AuthorityClock

    init(approve: Bool, clock: any AuthorityClock) {
        self.approve = approve
        self.clock = clock
    }

    var count: Int { lock.withLock { _count } }

    func authenticate(_ challenge: StepUpChallenge) async -> StepUpReceipt {
        lock.withLock { _count += 1 }
        return .answering(challenge, approved: approve, at: clock.now(), method: "counting")
    }
}

/// Lets a test hold the broker suspended inside step-up until it says go.
actor Gate {
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var isWaiting = false

    func wait() async {
        await withCheckedContinuation { continuation in
            waiter = continuation
            isWaiting = true
        }
    }

    func open() {
        waiter?.resume()
        waiter = nil
    }
}

final class BrokerRef: @unchecked Sendable {
    // @unchecked: assigned once before the broker is first used.
    var broker: AuthorityBroker?
}

struct Harness {
    let broker: AuthorityBroker
    let clock: ManualClock

    init(
        policy: any AuthorityPolicy = Ledger.referencePolicy,
        stepUp: ((ManualClock) -> any StepUpAuthenticator)? = nil,
        configuration: BrokerConfiguration = BrokerConfiguration(),
        clock: ManualClock = ManualClock()
    ) throws {
        self.clock = clock
        let authenticator = stepUp?(clock) ?? FixedStepUpAuthenticator(approving: true, clock: clock)
        broker = try AuthorityBroker(policy: policy, stepUp: authenticator, clock: clock, configuration: configuration)
    }

    func issue(
        _ agent: AgentPrincipal, _ scopes: Set<Scope>, parent: AgentCredential? = nil,
        key: any ProofKey = SoftwareProofKey(), lifetime: TimeInterval = 300
    ) async throws -> AgentCredential {
        let request: DelegationRequest
        if let parent {
            request = try parent.delegate(scopes, to: agent, childKey: key, lifetime: lifetime, at: clock.now())
        } else {
            request = DelegationRequest(
                subject: Ledger.subject, agent: agent, audience: Ledger.audience, scopes: scopes,
                requestedLifetime: lifetime, proofKey: key.publicKey
            )
        }
        let token = try await broker.exchange(request)
        return AgentCredential(token: token, key: key)
    }

    @discardableResult
    func call(_ credential: AgentCredential, _ op: ProtectedOperation, at date: Date? = nil) async throws -> Authorization {
        try await broker.authorize(try credential.present(for: op, at: date ?? clock.now()), for: op)
    }
}

func XCTAssertThrowsCode<T>(
    _ expected: String, file: StaticString = #filePath, line: UInt = #line,
    _ body: () async throws -> T
) async {
    do {
        _ = try await body()
        XCTFail("expected \(expected), but the call succeeded", file: file, line: line)
    } catch let error as AuthorityError {
        XCTAssertEqual(error.code, expected, "got \(error)", file: file, line: line)
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
}

func XCTAssertThrowsExactly<T>(
    _ expected: AuthorityError, file: StaticString = #filePath, line: UInt = #line,
    _ body: () async throws -> T
) async {
    do {
        _ = try await body()
        XCTFail("expected \(expected), but the call succeeded", file: file, line: line)
    } catch let error as AuthorityError {
        XCTAssertEqual(error, expected, file: file, line: line)
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
}

/// Parks any number of callers until `open()`.
actor MultiGate {
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var isOpen = false
    var waitingCount: Int { waiters.count }

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for w in pending { w.resume() }
    }
}
