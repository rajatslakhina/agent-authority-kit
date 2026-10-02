import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// MARK: - Clock

/// Time is injected everywhere. Expiry, proof freshness, step-up freshness and
/// revocation pruning are all time-based, and a test that has to `sleep` to
/// prove an expiry rule is a test nobody runs twice.
public protocol AuthorityClock: Sendable {
    func now() -> Date
}

public struct SystemClock: AuthorityClock {
    public init() {}
    public func now() -> Date { Date() }
}

/// A clock the caller advances by hand. Thread-safe; used by the tests and by the
/// adversarial suite so that "this token expired" is deterministic.
public final class ManualClock: AuthorityClock, @unchecked Sendable {
    // @unchecked: the only mutable state is `current`, and every access to it
    // goes through `lock`.
    private let lock = NSLock()
    private var current: Date

    public init(_ start: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        current = start
    }

    public func now() -> Date {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    /// Advances the clock. Non-finite or negative amounts are ignored rather
    /// than trapping or moving time backwards.
    public func advance(by seconds: TimeInterval) {
        guard seconds.isFinite, seconds > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        current = current.addingTimeInterval(seconds)
    }
}

// MARK: - Errors

/// Every refusal is typed. "Denied" with no reason is useless in an audit log
/// and impossible to write a regression test against.
public enum AuthorityError: Error, Sendable, Hashable, CustomStringConvertible {
    case invalidConfiguration(String)
    case invalidRequest(String)
    case policyDenied(String)
    /// The policy returned something the broker's own invariants forbid.
    case policyViolation(String)
    case delegationNotAttenuated
    case delegationTooDeep(limit: Int)
    case parentInvalid(String)
    case stepUpDeclined
    case stepUpMismatch
    case stepUpStale
    /// Revocation landed while the broker was suspended waiting for consent.
    case revokedDuringStepUp
    case tokenSignatureInvalid
    case tokenExpired
    case audienceMismatch
    case scopeNotGranted(String)
    case revoked(String)
    case proofKeyMismatch
    case proofSignatureInvalid
    case proofTokenBindingMismatch
    case proofTargetMismatch
    case proofStale
    case proofReplayed
    case replayCacheSaturated
    /// The revocation generation counter is exhausted; the broker refuses
    /// everything rather than silently stop revoking.
    case brokerSealed
    case cancelled

    /// The case name without its payload — stable for expectations and metrics.
    public var code: String {
        switch self {
        case .invalidConfiguration: return "invalidConfiguration"
        case .invalidRequest: return "invalidRequest"
        case .policyDenied: return "policyDenied"
        case .policyViolation: return "policyViolation"
        case .delegationNotAttenuated: return "delegationNotAttenuated"
        case .delegationTooDeep: return "delegationTooDeep"
        case .parentInvalid: return "parentInvalid"
        case .stepUpDeclined: return "stepUpDeclined"
        case .stepUpMismatch: return "stepUpMismatch"
        case .stepUpStale: return "stepUpStale"
        case .revokedDuringStepUp: return "revokedDuringStepUp"
        case .tokenSignatureInvalid: return "tokenSignatureInvalid"
        case .tokenExpired: return "tokenExpired"
        case .audienceMismatch: return "audienceMismatch"
        case .scopeNotGranted: return "scopeNotGranted"
        case .revoked: return "revoked"
        case .proofKeyMismatch: return "proofKeyMismatch"
        case .proofSignatureInvalid: return "proofSignatureInvalid"
        case .proofTokenBindingMismatch: return "proofTokenBindingMismatch"
        case .proofTargetMismatch: return "proofTargetMismatch"
        case .proofStale: return "proofStale"
        case .proofReplayed: return "proofReplayed"
        case .replayCacheSaturated: return "replayCacheSaturated"
        case .brokerSealed: return "brokerSealed"
        case .cancelled: return "cancelled"
        }
    }

    public var description: String {
        switch self {
        case .invalidConfiguration(let m): return "invalid configuration: \(m)"
        case .invalidRequest(let m): return "invalid request: \(m)"
        case .policyDenied(let m): return "policy denied: \(m)"
        case .policyViolation(let m): return "policy violation: \(m)"
        case .delegationNotAttenuated: return "sub-delegation must be a subset of the parent"
        case .delegationTooDeep(let limit): return "delegation chain longer than \(limit)"
        case .parentInvalid(let m): return "parent token invalid: \(m)"
        case .stepUpDeclined: return "user declined step-up"
        case .stepUpMismatch: return "step-up receipt is for a different challenge"
        case .stepUpStale: return "step-up receipt is stale"
        case .revokedDuringStepUp: return "revoked while waiting for consent"
        case .tokenSignatureInvalid: return "token MAC invalid"
        case .tokenExpired: return "token expired"
        case .audienceMismatch: return "token audience mismatch"
        case .scopeNotGranted(let s): return "scope not granted: \(s)"
        case .revoked(let m): return "revoked: \(m)"
        case .proofKeyMismatch: return "proof key does not match token binding"
        case .proofSignatureInvalid: return "proof signature invalid"
        case .proofTokenBindingMismatch: return "proof is bound to a different token"
        case .proofTargetMismatch: return "proof names a different target"
        case .proofStale: return "proof outside freshness window"
        case .proofReplayed: return "proof replayed"
        case .replayCacheSaturated: return "replay cache saturated (failing closed)"
        case .brokerSealed: return "broker sealed"
        case .cancelled: return "cancelled"
        }
    }
}

// MARK: - Digests and MACs

enum Digest {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func sha256Hex(_ data: Data) -> String {
        sha256(data).map { String(format: "%02x", $0) }.joined()
    }

    static func mac(_ data: Data, key: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    /// Constant-time MAC comparison — `==` on `Data` short-circuits and leaks how
    /// many leading bytes matched.
    static func verifyMAC(_ mac: Data, for data: Data, key: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: data, using: SymmetricKey(data: key))
    }

    static func randomKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }
}

/// Deterministic, unambiguous byte encoding for anything that gets signed or
/// MAC'd. Every variable-length field is length-prefixed, so `("ab","c")` and
/// `("a","bc")` can never produce the same bytes. JSON is deliberately not used:
/// its key order and number formatting are not canonical across encoders.
struct CanonicalEncoder {
    private(set) var bytes = Data()

    mutating func append(_ value: UInt64) {
        withUnsafeBytes(of: value.bigEndian) { bytes.append(contentsOf: $0) }
    }

    mutating func append(_ data: Data) {
        // `count` is never negative, so this conversion cannot lose information.
        append(UInt64(truncatingIfNeeded: data.count))
        bytes.append(data)
    }

    mutating func append(_ string: String) {
        append(Data(string.utf8))
    }

    mutating func append(_ date: Date) {
        // Bit pattern, not `Int(seconds)`: no conversion that could trap on NaN,
        // infinity or out-of-range values, and no rounding.
        append(date.timeIntervalSince1970.bitPattern)
    }

    mutating func append(_ scopes: Set<Scope>) {
        let sorted = scopes.sorted()
        append(UInt64(truncatingIfNeeded: sorted.count))
        for scope in sorted {
            append(scope.name)
            append(UInt64(truncatingIfNeeded: scope.tier.rawValue))
        }
    }

    mutating func append(_ strings: [String]) {
        append(UInt64(truncatingIfNeeded: strings.count))
        for s in strings { append(s) }
    }
}

// MARK: - Saturating arithmetic

extension UInt64 {
    /// `self + 1`, stopping at `.max` instead of trapping.
    var saturatingIncrement: UInt64 {
        let (result, overflow) = addingReportingOverflow(1)
        return overflow ? .max : result
    }
}

extension TimeInterval {
    /// True for a usable duration: finite and strictly positive.
    var isUsableDuration: Bool { isFinite && self > 0 }
}
