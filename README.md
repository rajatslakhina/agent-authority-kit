# AgentAuthority

**Your app now has three kinds of agents calling into it — Siri through App Intents, your own on-device model through tool calls, and remote MCP clients. Most apps let all three borrow the user's session. This package gives each of them its own identity, a token that expires in minutes, a key it has to prove it holds, and a revocation path that reaches tasks already in flight.**

[![CI](https://github.com/rajatslakhina/agent-authority-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/rajatslakhina/agent-authority-kit/actions/workflows/ci.yml)
![Swift 6](https://img.shields.io/badge/Swift-6.0%20language%20mode-orange)
![Platforms](https://img.shields.io/badge/platforms-iOS%2017%20%7C%20macOS%2014%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Demo app: **[agent-authority-kit-demo](https://github.com/rajatslakhina/agent-authority-kit-demo)** — a separate Xcode project that consumes this package as a remote Swift package — any released 1.x (`upToNextMajorVersion` from `1.0.0`), never a branch or a local path.

---

## The problem

App Intents are how Siri and Shortcuts get into an app, and the same use cases are now also being called by in-app LLM tool loops and by MCP clients. The usual integration is "the agent runs with the user's session": whatever the user can do, the agent can do, for as long as the session lives, and the audit log says *the user* did it.

That is three separate failures:

1. **No least privilege.** A summarisation tool call holds the power to move money.
2. **No attribution.** "User 42 initiated a payment" when it was a remote client acting on a prompt the user never saw.
3. **No kill switch that works mid-task.** Revoking a session does nothing to an agent that already has a bearer token in memory and is six steps into a ten-step plan.

The OpenID Foundation's *Identity Management for Agentic AI* paper makes the general argument: agents need their own identities and delegated, attenuable authority rather than borrowed sessions. This package is that argument, built for one app process, in Swift.

## What it does

```
App Intent / model tool call / MCP request
        │
        ▼
AuthorityBroker.exchange(DelegationRequest)          ← OAuth 2.0 Token Exchange shape (RFC 8693)
        │  1. validate request (finite lifetime, P-256 proof key, non-empty scopes)
        │  2. sub-delegation? parent valid · caller proves it holds the parent's key (DPoP)
        │     · scopes ⊆ parent · same subject/audience · no cycles
        │  3. policy.evaluate → allow(maxLifetime, stepUp, maxChain) | deny        (product-owned table)
        │  4. broker floor: every scope ≥ .sensitive needs consent, whatever the policy said
        │  5. step-up ── await StepUpAuthenticator ──▶  (suspension point: revocations can land here)
        │  6. re-check revocation witness, receipt binding, receipt freshness, parent expiry
        │  7. mint: jti · grantID · act chain · audience · scopes · exp · generation · cnf.jkt · HMAC
        ▼
CapabilityToken  ──────────────  bound to the agent's key (Secure Enclave where available)

Every protected call:
AuthorityBroker.authorize(Presentation(token, DPoPProof), for: ProtectedOperation)
        MAC → expiry → revocation (token · ancestor tokens · grant · every agent in the act chain · generation)
        → audience → scope → proof key = cnf.jkt → proof signature → proof bound to this token
        → proof names this method + target → proof fresh → proof id never seen before
```

Every decision — issue, delegate, consent, authorize, deny, revoke — is appended to a **keyed hash-chained audit log**.

## Why this matters at lead level

The interesting part of this design is not the token format. It is four decisions a reviewer will push on, each with a cost the design accepts on purpose.

### 1. Re-check after the `await`, against a witness — not before it

`AuthorityBroker` is an actor, so minting, revocation and the replay cache are serialized. But step-up consent is an `await`, and an actor is *reentrant*: while the user is looking at the prompt, `revokeAgent` and `revokeAll` run. A broker that checks revocation before the prompt and mints after it will mint a live token for an agent the user just killed.

The broker captures a revocation **witness** (generation, the revocation instants of every agent in the chain, grant and parent-token state) before suspending, and compares it after. Any difference aborts with `.revokedDuringStepUp`. Parent expiry, cancellation and receipt freshness are also re-checked after the suspension. Tests drive this deterministically: a scripted authenticator calls `revokeAll()` / `revokeGrant()` *from inside* the consent callback; a revocation of an unrelated agent during consent must **not** abort.

*Rejected:* holding a lock across the prompt (an actor can't, and a lock held for a human-scale wait blocks every other agent); a version counter on the whole broker (any revocation anywhere would abort every pending consent).

### 2. Bounded revocation that fails closed

Revocation tables grow forever unless something removes entries, and removing the wrong one *un-revokes a token*. Every token's lifetime is capped by `hardMaxLifetime`. A token or grant entry recorded at `t` can only match tokens minted before `t` (nothing is sub-delegated from a revoked grant), and an agent entry at `t` only matches tokens issued at or before `t` — agent revocation is an instant, not a ban. So every entry can safely be forgotten after `t + hardMaxLifetime`. If the table is full of entries that are still load-bearing, the broker bumps the **generation** — revoking everything — instead of dropping one.

That fallback is itself written to the audit log. *Cost accepted:* under revocation storms every agent must re-grant. *Alternative rejected:* LRU eviction, which is a silent resurrection bug. If the generation counter itself is exhausted (`UInt64.max`), the broker **seals** and refuses everything rather than stop revoking.

The DPoP replay cache follows the same rule: when it is full of still-fresh proof ids it returns `.replayCacheSaturated` rather than evict one, because evicting a live id makes that exact proof replayable.

### 3. All-or-nothing scopes, and a broker floor under the policy

OAuth lets an authorization server silently narrow scope. For an agent that is worse than a refusal: it plans a multi-step task around powers it doesn't have and fails halfway, after side effects. The policy is all-or-nothing.

The policy is a protocol (`AuthorityPolicy`) because product teams own it and it will be wrong sometimes. So the broker does not trust it: it rejects non-finite or non-positive lifetimes, step-up sets that name unrequested scopes, and chain limits below the actual chain; it clamps every lifetime to `hardMaxLifetime` and refuses any chain longer than `hardMaxChainLength`; and it requires consent for every sensitive scope even if the policy asks for none. `AdversarialSuiteTests.testSuiteFailsAgainstABrokenPolicy` runs the whole suite against a policy that grants everything and asserts, for all 20 scenarios, that exactly the two policy-dependent ones now fail and the other 18 — held by the broker's own invariants — still pass.

### 4. HMAC tokens, P-256 proofs, keyed audit chain

- **Token integrity is HMAC-SHA256**, not a JWS signature: issuer and verifier are the same process, so an asymmetric signature buys nothing and costs a signature verification per call. Revisit if tokens ever leave the device.
- **Proof of possession is ECDSA P-256** with the key in the Secure Enclave when the device has one (`ProofKeyFactory.strongestAvailable()`). Every call *and every sub-delegation* must carry a fresh, single-use proof signed by the key the token is bound to, so a token exfiltrated from memory or logs can neither be presented nor re-delegated to a key the thief controls. The iOS Simulator has no enclave; the factory falls back to a software key and the demo says so on screen.
- **The audit log is an HMAC chain**, not a bare hash chain: anyone who can write the file can recompute a bare hash chain end to end. There is a test that does exactly that with its own key and shows the broker rejects it. *Stated limits:* a chain cannot detect truncation of its own tail, and because the anchor and `droppedCount` are not themselves authenticated, it cannot detect entries dropped from the front and re-anchored either. Both need `auditHead` (and the anchor) exported to somewhere the attacker cannot write. The log is bounded by rolling old entries off and keeping the last rolled-off MAC as the new anchor.

Every signed or MAC'd structure uses a length-prefixed canonical encoding (`CanonicalEncoder`), never JSON — key order and number formatting are not canonical across encoders, and `("ab","c")` must not collide with `("a","bc")`.

## The adversarial suite

`AdversarialSuite.run(policy:)` replays 20 tool-call sequences — 18 attacks and 2 baselines that must be allowed — against a fresh broker each and reports, per scenario, *which error* stopped it. Expectations are matched on the error case, not on "it threw": a stolen-token attempt rejected because the token happened to expire would pass a looser suite while the key-binding check was broken.

| Scenario | Expected outcome |
|---|---|
| Baseline read · Baseline payment with consent | allowed |
| Stolen token (attacker's own key) | `proofKeyMismatch` |
| Stolen token re-delegated to the attacker's key | `proofKeyMismatch` |
| Proof replay | `proofReplayed` |
| Proof lifted to another endpoint | `proofTargetMismatch` |
| Wrong audience | `audienceMismatch` |
| Scope escalation | `scopeNotGranted` |
| Token edited in transit | `tokenSignatureInvalid` |
| Sub-delegation widening | `delegationNotAttenuated` |
| Delegation to a remote client | `delegationTooDeep` |
| Remote client asks to pay | `policyDenied` |
| User declines | `stepUpDeclined` |
| Consent for another grant | `stepUpMismatch` |
| Stale consent | `stepUpStale` |
| Revocation during consent | `revokedDuringStepUp` |
| Expired token | `tokenExpired` |
| In-flight revocation · Revoked delegator · Kill switch | `revoked` |

## Usage

```swift
.package(url: "https://github.com/rajatslakhina/agent-authority-kit.git", from: "1.0.0")
```

```swift
import AgentAuthority

let broker = try AuthorityBroker(policy: myPolicy, stepUp: myConsentUI)

// When an agent arrives:
let key = ProofKeyFactory.strongestAvailable()          // Secure Enclave if present
let token = try await broker.exchange(DelegationRequest(
    subject: userID, agent: AgentPrincipal(id: "siri-intent", kind: .appIntent, displayName: "Siri"),
    audience: "ledger", scopes: [Ledger.initiatePayment], requestedLifetime: 120, proofKey: key.publicKey))
let credential = AgentCredential(token: token, key: key)

// On every protected step of the agent's task:
let auth = try await broker.authorize(try credential.present(for: Ledger.pay, at: .now), for: Ledger.pay)
// auth.actorChain == ["siri-intent"], auth.subject == userID

// Sub-delegation proves possession of the parent's key and can only narrow:
let child = try await broker.exchange(try credential.delegate(
    [Ledger.initiatePayment], to: modelAgent, childKey: ProofKeyFactory.strongestAvailable(),
    lifetime: 60, at: .now))

// From settings, or a server push:
await broker.revokeAgent("siri-intent")   // the next step of any in-flight task fails
await broker.revokeToken(token.id)        // this token and everything delegated from it
await broker.revokeGrant(token.grantID)   // the whole delegation tree
await broker.revokeAll()                  // kill switch
```

`AgentAuthorityUI` adds `AuthorityConsoleModel` (Observation-based, unit-tested on Linux) and `AuthorityConsoleView`, the SwiftUI console the demo app runs.

## Layout

| Module | Contents |
|---|---|
| `AgentAuthority` | `AuthorityBroker` (actor), `CapabilityToken`, `DPoPProof`, `ProofKey` / `SecureEnclaveProofKey` / `SoftwareProofKey`, `AuthorityPolicy` / `StaticAuthorityPolicy`, `StepUpAuthenticator`, revocation state, replay cache, audit log, `AdversarialSuite`, `Ledger` fixture |
| `AgentAuthorityUI` | `AuthorityConsoleModel`, `ConsentBridge` (weak back-reference to avoid a model→broker→bridge→model cycle), `AuthorityConsoleView` (SwiftUI, compiled only where SwiftUI exists) |

No app or executable target lives in this package. The runnable app is the separate [demo repo](https://github.com/rajatslakhina/agent-authority-kit-demo).

Dependencies: on Apple platforms the code links only CryptoKit. [apple/swift-crypto](https://github.com/apple/swift-crypto) (CryptoKit's API-compatible open-source twin) is declared so the same code builds and is tested on Linux; it is linked only on Linux, but SwiftPM still resolves and fetches it (and `swift-asn1`) for every consumer, including Apple ones.

## Running the tests

```bash
swift test                                               # macOS
swift test -Xlinker --allow-shlib-undefined              # Linux (see below)
bash Scripts/mutation-check.sh                           # macOS; prefix EXTRA_TEST_FLAGS="-Xlinker --allow-shlib-undefined" on Linux
```

On Linux the toolchain's `libswiftObservation.so` references `swift::threading::fatal` without any shipped library exporting it, so linking a test binary that uses Observation fails under the linker's default `--no-allow-shlib-undefined`. The symbol is only reached on a fatal path; the flag is confined to the Linux test link.

`Scripts/mutation-check.sh` (run it with `bash`; web uploads drop the executable bit) is the answer to "would the tests notice?". It applies nine mutations, each removing one guarantee this README claims — the post-consent witness re-check, the replay-window boundary, the consent floor, the proof-key binding, act-chain revocation, fail-closed revocation capacity, the post-suspension parent re-check, sub-delegation proof of possession, and the audit MAC check — and requires `swift test` to fail for every one.

## What it does not do

- **It does not authenticate the caller.** `AgentPrincipal` (id and kind) is asserted by whoever calls `exchange`. The host app must authenticate each channel — the App Intent entry point, its own model loop, the MCP transport — and map it to the right principal; a remote client that is mapped carelessly to `.appIntent` gets App-Intent policy. The broker gives each agent its own *authority*; establishing *who* the agent is stays the host's job.
- It is an **in-process** broker. Tokens are never meant to leave the device; a server-side resource server would want JWS + key discovery instead of HMAC.
- `StepUpAuthenticator` is the seam for consent. The UI module ships an in-app consent sheet; a LocalAuthentication (Face ID / passcode) authenticator is the obvious production implementation and is not included.
- Broker keys are generated per process in the demo. In production they belong in the Keychain.

## Verification

What was actually run, and what was not:

- **CI** ([Actions](https://github.com/rajatslakhina/agent-authority-kit/actions/workflows/ci.yml)), on every push to `main`:
  - *Linux* (`swift:6.1-noble` container): `swift build -Xswiftc -warnings-as-errors`, then `swift test -Xlinker --allow-shlib-undefined`. On the first run: **69 tests, 0 failures**.
  - *macOS* (`macos-15`, Xcode 16.4, Swift 6.1.2): `swift test -Xswiftc -warnings-as-errors` against the CryptoKit code path — **69 tests, 0 failures, 0 warnings** — then `xcodebuild build -scheme AgentAuthority-Package -destination 'generic/platform=iOS Simulator'` — **BUILD SUCCEEDED**, which is the only place the SwiftUI views are compiled.
- **Locally**, from a clean build on Swift 6.1.2 / Ubuntu 24.04: `swift test -Xswiftc -warnings-as-errors -Xlinker --allow-shlib-undefined` — **69 tests, 0 failures, 0 warnings**.
- **Mutation check** (`Scripts/mutation-check.sh`, Linux): **9 of 9 mutations caught** — each one, applied alone, makes `swift test` fail, and the script prints which tests caught it. (Run in two passes: the first was interrupted while running #6, so #6–#9 were re-run.)
- **Demo app**: its own CI resolves this package from GitHub (it resolved `agent-authority-kit @ 1.0.0`) and builds the app for the iOS Simulator — **BUILD SUCCEEDED**.
- **Not done: the app has not been run on a Simulator.** Computer-use access to Xcode and Simulator was granted for this release, but the Mac's screen was locked, and macOS blocks every click while it is. Three attempts were refused the same way. So the app was compiled for the Simulator but never launched there, and no screenshots exist. "It builds for the Simulator" is not a claim that it ran.

## License

MIT
