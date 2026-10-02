import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// MARK: - Proof keys

/// The key an agent proves possession of on every call (DPoP, RFC 9449).
/// A leaked token without this key is useless: the broker refuses any
/// presentation whose proof was not signed by the key the token was bound to.
public protocol ProofKey: Sendable {
    /// Raw P-256 public key (x‖y, 64 bytes).
    var publicKey: Data { get }
    func sign(_ data: Data) throws -> Data
}

extension ProofKey {
    /// `cnf.jkt`-style thumbprint: SHA-256 of the raw public key, hex.
    public var thumbprint: String { ProofVerifier.thumbprint(of: publicKey) }
}

/// A software P-256 key. Used on Linux, in tests, and on the iOS Simulator,
/// which has no Secure Enclave.
public struct SoftwareProofKey: ProofKey {
    // Stored as bytes rather than as `P256.Signing.PrivateKey` so the type is
    // `Sendable` on every SDK, whether or not the platform's crypto types are.
    private let privateKeyBytes: Data
    public let publicKey: Data

    public init() {
        let key = P256.Signing.PrivateKey()
        privateKeyBytes = key.rawRepresentation
        publicKey = key.publicKey.rawRepresentation
    }

    public func sign(_ data: Data) throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: privateKeyBytes).signature(for: data).rawRepresentation
    }
}

#if canImport(CryptoKit) && !os(Linux)
/// A Secure-Enclave-resident P-256 key. The private key never leaves the
/// enclave, so the token binding survives even a full memory dump of the app.
@available(iOS 17.0, macOS 14.0, *)
public struct SecureEnclaveProofKey: ProofKey {
    /// The enclave-wrapped key blob. It is only usable by this device's
    /// Secure Enclave; the private key itself never exists in app memory.
    private let wrappedKey: Data
    public let publicKey: Data

    /// `false` on the Simulator and on Macs without a Secure Enclave.
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public init() throws {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        wrappedKey = key.dataRepresentation
        publicKey = key.publicKey.rawRepresentation
    }

    public func sign(_ data: Data) throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrappedKey).signature(for: data).rawRepresentation
    }
}
#endif

/// Picks the strongest key the device offers.
public enum ProofKeyFactory {
    public static func strongestAvailable() -> any ProofKey {
        #if canImport(CryptoKit) && !os(Linux)
        if SecureEnclaveProofKey.isAvailable, let key = try? SecureEnclaveProofKey() {
            return key
        }
        #endif
        return SoftwareProofKey()
    }

    public static var strongestAvailableIsHardwareBacked: Bool {
        #if canImport(CryptoKit) && !os(Linux)
        return SecureEnclaveProofKey.isAvailable
        #else
        return false
        #endif
    }
}

enum ProofVerifier {
    static func thumbprint(of publicKey: Data) -> String {
        Digest.sha256Hex(publicKey)
    }

    static func isValid(signature: Data, for data: Data, publicKey: Data) -> Bool {
        guard
            let key = try? P256.Signing.PublicKey(rawRepresentation: publicKey),
            let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(sig, for: data)
    }

    static func isWellFormedPublicKey(_ publicKey: Data) -> Bool {
        (try? P256.Signing.PublicKey(rawRepresentation: publicKey)) != nil
    }
}

// MARK: - Capability token

/// A short-lived, audience- and scope-bound, proof-of-possession-bound token.
///
/// Integrity is an HMAC under a key only the broker holds. That is a deliberate
/// choice over an asymmetric signature (JWS): the issuer and the verifier are
/// the *same* process, so a public verification key buys nothing and costs a
/// signature per call on the hot path.
public struct CapabilityToken: Sendable, Hashable {
    public let id: String
    /// Shared by a root token and every token sub-delegated from it, so
    /// revoking the grant kills the whole tree.
    public let grantID: String
    public let subject: String
    /// The `act` chain, outermost delegator first; the last entry holds the token.
    public let actorChain: [String]
    /// Ids of every token this one was delegated from, root first. Covered by
    /// the MAC, so revoking any ancestor token reaches every descendant.
    public let ancestorTokenIDs: [String]
    public let agentKind: AgentKind
    public let audience: String
    public let scopes: Set<Scope>
    public let issuedAt: Date
    public let expiresAt: Date
    /// Revocation generation at mint time; `revokeAll()` bumps the broker's.
    public let generation: UInt64
    /// `cnf.jkt`: thumbprint of the key every presentation must be signed with.
    public let confirmationThumbprint: String
    public let mac: Data

    /// The agent holding this token. `actorChain` is never empty for a token the
    /// broker minted; an empty chain (forged) yields `""`, which matches no agent.
    public var holderID: String { actorChain.last ?? "" }

    init(
        id: String, grantID: String, subject: String, actorChain: [String], ancestorTokenIDs: [String], agentKind: AgentKind,
        audience: String, scopes: Set<Scope>, issuedAt: Date, expiresAt: Date,
        generation: UInt64, confirmationThumbprint: String, mac: Data
    ) {
        self.id = id
        self.grantID = grantID
        self.subject = subject
        self.actorChain = actorChain
        self.ancestorTokenIDs = ancestorTokenIDs
        self.agentKind = agentKind
        self.audience = audience
        self.scopes = scopes
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.generation = generation
        self.confirmationThumbprint = confirmationThumbprint
        self.mac = mac
    }

    var signingInput: Data {
        var e = CanonicalEncoder()
        e.append("agent-authority/token/v1")
        e.append(id)
        e.append(grantID)
        e.append(subject)
        e.append(actorChain)
        e.append(ancestorTokenIDs)
        e.append(agentKind.rawValue)
        e.append(audience)
        e.append(scopes)
        e.append(issuedAt)
        e.append(expiresAt)
        e.append(generation)
        e.append(confirmationThumbprint)
        return e.bytes
    }

    /// `ath`: what a DPoP proof commits to.
    public var hashForProof: String { Digest.sha256Hex(signingInput + mac) }

    /// Returns a copy with different scopes but the *original* MAC. Exists so the
    /// adversarial suite and tests can model an attacker editing a token in
    /// transit; the broker must reject the result.
    public func tampered(scopes newScopes: Set<Scope>) -> CapabilityToken {
        CapabilityToken(
            id: id, grantID: grantID, subject: subject, actorChain: actorChain, ancestorTokenIDs: ancestorTokenIDs, agentKind: agentKind,
            audience: audience, scopes: newScopes, issuedAt: issuedAt, expiresAt: expiresAt,
            generation: generation, confirmationThumbprint: confirmationThumbprint, mac: mac
        )
    }
}

// MARK: - DPoP proof

/// A per-request proof of possession. Commits to the token (`ath`), the method
/// and the exact target, and carries its own id so it can be used once.
public struct DPoPProof: Sendable, Hashable {
    public let id: String
    public let method: String
    public let target: String
    public let issuedAt: Date
    public let tokenHash: String
    public let publicKey: Data
    public let signature: Data

    static func signingInput(id: String, method: String, target: String, issuedAt: Date, tokenHash: String, publicKey: Data) -> Data {
        var e = CanonicalEncoder()
        e.append("agent-authority/dpop/v1")
        e.append(id)
        e.append(method)
        e.append(target)
        e.append(issuedAt)
        e.append(tokenHash)
        e.append(publicKey)
        return e.bytes
    }

    var signingInput: Data {
        Self.signingInput(id: id, method: method, target: target, issuedAt: issuedAt, tokenHash: tokenHash, publicKey: publicKey)
    }

    public static func make(
        for token: CapabilityToken,
        method: String,
        target: String,
        key: any ProofKey,
        at issuedAt: Date,
        id: String = UUID().uuidString
    ) throws -> DPoPProof {
        let publicKey = key.publicKey
        let tokenHash = token.hashForProof
        let input = signingInput(id: id, method: method, target: target, issuedAt: issuedAt, tokenHash: tokenHash, publicKey: publicKey)
        let signature = try key.sign(input)
        return DPoPProof(id: id, method: method, target: target, issuedAt: issuedAt, tokenHash: tokenHash, publicKey: publicKey, signature: signature)
    }
}

/// Token plus proof: what an agent hands the broker for every protected call.
public struct Presentation: Sendable, Hashable {
    public let token: CapabilityToken
    public let proof: DPoPProof

    public init(token: CapabilityToken, proof: DPoPProof) {
        self.token = token
        self.proof = proof
    }
}

/// Agent-side convenience: a token plus the key it is bound to.
public struct AgentCredential: Sendable {
    public let token: CapabilityToken
    public let key: any ProofKey

    public init(token: CapabilityToken, key: any ProofKey) {
        self.token = token
        self.key = key
    }

    /// Proof of possession of this credential's token, for sub-delegating it.
    public func delegationProof(at date: Date) throws -> DPoPProof {
        try DPoPProof.make(
            for: token, method: DelegationRequest.delegationMethod,
            target: DelegationRequest.delegationTarget(for: token.audience), key: key, at: date
        )
    }

    /// Builds a sub-delegation request that attenuates this credential's token
    /// to `scopes` for `agent`, bound to `childKey`.
    public func delegate(
        _ scopes: Set<Scope>, to agent: AgentPrincipal, childKey: any ProofKey,
        lifetime: TimeInterval, at date: Date
    ) throws -> DelegationRequest {
        DelegationRequest(
            subject: token.subject, agent: agent, audience: token.audience, scopes: scopes,
            requestedLifetime: lifetime, proofKey: childKey.publicKey,
            parent: token, parentProof: try delegationProof(at: date)
        )
    }

    public func present(for operation: ProtectedOperation, at date: Date) throws -> Presentation {
        let proof = try DPoPProof.make(for: token, method: operation.method, target: operation.target, key: key, at: date)
        return Presentation(token: token, proof: proof)
    }
}
