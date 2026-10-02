#!/usr/bin/env bash
# Mutation check: each mutation removes or weakens one guarantee the README
# claims. For each, the package is copied to a scratch directory, the mutation
# is applied, and `swift test` is run. A mutation that the test suite does NOT
# catch is a claim without a test, and fails this script.
#
# Usage: Scripts/mutation-check.sh            (from the package root)
#        EXTRA_TEST_FLAGS="-Xlinker --allow-shlib-undefined" Scripts/mutation-check.sh   (Linux)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${MUTATION_WORKDIR:-$(mktemp -d)}"
SRC=Sources/AgentAuthority

# name | file | perl substitution (applied with -0pe, must change the file)
MUTATIONS=(
  "revocation witness not re-checked after step-up|$SRC/AuthorityBroker.swift|s/parentTokenID: request.parent\?.id\) == witness else/parentTokenID: request.parent?.id) == witness || true else/"
  "replay cache forgets a proof at the exact window boundary|$SRC/State.swift|s/exp >= now \{ return .replayed \}/exp > now { return .replayed }/"
  "broker consent floor removed (policy alone decides)|$SRC/AuthorityBroker.swift|s/let stepUpScopes = policyStepUp.union\(floor\)/let stepUpScopes = policyStepUp/"
  "proof key not checked against the token's cnf thumbprint|$SRC/AuthorityBroker.swift|s/== token.confirmationThumbprint else/== token.confirmationThumbprint || true else/"
  "only the token holder, not the whole act chain, is checked for revocation|$SRC/State.swift|s/for actor in token.actorChain \{/for actor in token.actorChain.suffix(1) {/"
  "full revocation table evicts instead of failing closed|$SRC/State.swift|s/fail closed.\n            revokeAll\(\)/fail closed.\n            tokens.removeAll()/"
  "parent not re-validated after the step-up suspension|$SRC/AuthorityBroker.swift|s/if let problem = problem\(with: parent, at: issuedAt\) \{ throw .parentInvalid\(problem\) \}//"
  "sub-delegation does not verify proof of possession of the parent|$SRC/AuthorityBroker.swift|s/            try verifyProof\(\n                parentProof.*?now: start\n            \)\n//s"
  "audit chain verified by linkage only, MAC not checked|$SRC/State.swift|s/guard Digest.verifyMAC\(entry.mac, for: input, key: key\) else/guard true else/"
)

caught=0; missed=0; i=0
for m in "${MUTATIONS[@]}"; do
  i=$((i+1))
  IFS='|' read -r name file expr <<< "$m"
  dir="$WORK/m$i"
  rm -rf "$dir"; mkdir -p "$dir"
  (cd "$ROOT" && tar cf - --exclude=.build --exclude=.swiftpm .) | (cd "$dir" && tar xf -)
  before=$(cksum < "$dir/$file")
  perl -0pi -e "$expr" "$dir/$file"
  if [ "$(cksum < "$dir/$file")" = "$before" ]; then
    echo "SETUP ERROR  #$i $name: substitution did not apply"; missed=$((missed+1)); continue
  fi
  if (cd "$dir" && swift test ${EXTRA_TEST_FLAGS:-} > "$dir/test.log" 2>&1 < /dev/null); then
    echo "MISSED       #$i $name"; missed=$((missed+1))
  else
    if grep -q "error: emit-module\|error: compile command failed" "$dir/test.log"; then
      echo "SETUP ERROR  #$i $name: mutant does not compile"; missed=$((missed+1))
    else
      failing=$(grep -E "^Test Case .* failed" "$dir/test.log" | sed -E "s/^Test Case '([^']+)'.*/\1/" | sort -u | tr '\n' ' ')
      echo "CAUGHT       #$i $name  ->  $failing"; caught=$((caught+1))
    fi
  fi
done
echo "mutations caught: $caught / ${#MUTATIONS[@]}"
[ "$missed" -eq 0 ]
