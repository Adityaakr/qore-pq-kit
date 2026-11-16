# How AI was used to build qore-pq-kit

A dated log of the workflow, what the AI agents produced and what the human
owner decided. It is kept from the first pull request and extended as work
goes on.

## The workflow

- **One human owner** sets the goals and makes every decision that is theirs:
  the design, product choices, anything that needs a sign-in (the QoreChain
  dashboard faucet, project pages), anything sent to the organisers, and every
  merge.
- **An orchestrator agent ("Firstmate")** turns the owner's intent into written
  task briefs, dispatches them to worker agents, relays decisions and blockers,
  and never merges on its own authority.
- **Worker agents** (Claude Code, model Claude Opus 5.5) each get one brief and
  work alone in a disposable git worktree, so parallel work cannot collide. A
  worker reports through a status file and opens pull requests; a pull request
  is the only way work reaches `main`, and the owner reviews and merges it.
- **Secrets never pass through agent output.** Keys are created by scripts into
  files outside the repository with 0600 permissions; scripts print addresses
  only.

## Log

### 15 November 2026: design

A design worker wrote one combined design for the three Peal entries and this
kit. **Owner decisions** (all nine recommendations approved): one shared kit
distributed by git tags, nothing on npm; Apache-2.0; the auction's bids sealed
as ML-KEM-1024 envelopes of Shamir key shares that the contract recombines; a
2-of-3 ML-DSA signer set for the treasury; the drill worker's `kit/` moves into
this repository with its history once merged.

### 16 November 2026: threshold module (this worker)

One worker, one brief ("the shared toolkit: threshold module first, because the
auction depends on it; then the signer set, the testnet spikes, messaging, REST
and smart-account scripts"). It wrote:

- `src/threshold/Shamir.sol` and `src/threshold/SealedSlot.sol`, with unit,
  fuzz and fail-closed tests (mocked modexp returning nothing, a wrong value or
  reverting);
- `scripts/threshold.ts` (split, combine, seal each share with QoreSeal,
  open, verify a member's on-chain keys) and its vitest suite, including
  envelope binding and a lying-REST case;
- `scripts/vectors.ts` and `vectors/threshold.json`, checked byte for byte by
  Foundry; it confirmed the Foundry test fails when one vector byte is changed;
- a live probe that runs the Solidity libraries on the testnet through one
  `eth_call`, which matched every vector;
- cross-version tests for QoreSign 0.1.0 and 0.2.0 on QoreSeal recipient cards.

It read Peal's code read-only to credit the design rules it follows, and copied
no Peal file. No transaction was sent.

### 16 November 2026: the drill kit moves in (this worker)

After the owner merged the drill PR in peal-tender, the worker ran
`git subtree split --prefix=kit` on peal-tender `main` and merged the result
here with `--allow-unrelated-histories`, keeping the kit's fest-dated commit
(a9e6e93). It changed none of the kit's files; it resolved only the shared
config and the README, and tagged the result `v0.1.0`. The pull request was
then squash-merged, so `main` holds the kit as part of one commit (3682f19);
the tag `v0.1.0` still points at the unsquashed history with the kit's own
commit.

### 16 November 2026: PqAuthSet (this worker)

It wrote `src/PqAuthSet.sol` (t-of-n ML-DSA-87 signer set on `PqAuth`, owner
decision D9) with 36 Foundry tests, among them replay, wrong member, wrong
order, mixing single-signer and quorum signatures, membership changes, key
rotation on chain and fuzzed quorums; `scripts/pqauthset.ts` with its vitest
suite; and `vectors/pqauthset.json`, checked from both sides. It folded the
action under a set domain so that a single-signer signature and a quorum share
can never be swapped for each other, a choice made by the worker and recorded
here for the owner's review.

### 16 November 2026: messaging and REST (this worker)

It wrote `scripts/messaging.ts` (instructions signed with QoreSign and sealed
with QoreSeal, verified against the sender's ML-DSA key read from the chain),
`scripts/rest.ts` (a typed REST reader and a read-only allowlisting proxy) and
`scripts/rest-proxy.ts`. It tested them with vitest, including forgery, a
stolen classical key, tampering, expiry, replay and envelope re-filing. It ran
the proxy locally against the public testnet: an allowed read came back with
CORS headers and a POST was refused. No transaction was sent.

### 16 November 2026: spikes S1, S3 and S5 (this worker)

**Owner decision:** fund the spike accounts with one 10 QOR transfer from the
drill account, as a one-time exception, leaving at least 5 QOR there. The
worker made exactly that transfer, a plain native send, after checking the
sender address, the amount and the balance left. Then, on throwaway accounts,
it registered two ML-DSA keys (one with a proof of possession, one without)
and one ML-KEM key, and ran `verifyMember` against the live chain. The owner
supplied the faucet evidence for S5, and the worker checked the EVM side
read-only. It also cut `pqauthset.ts` loose from the SDK so the browser
bundle fell from 2.7 MB to 162 KB.

### 16 November 2026: spike S2 and the smart-account module (this worker)

On throwaway accounts funded from the spike bank, the worker deployed a
throwaway target contract, linked an agent key to an owner account with a
spending rule, and relayed four `MsgExecuteEVM` calls: allowed, over the
limit, off target and a replay. It recorded each outcome and transaction hash,
then wrote `scripts/smart-account.ts` from what worked, and re-ran the spike
through the module to prove it live. No drill account or drill contract was
used.

### 16 November 2026: register-kem, card and fund (this worker)

It added the three commands the design lists for the kit's CLI. `register-kem`
publishes an account's ML-KEM-1024 key and refuses to replace a different
one by accident; `card` signs a QoreSeal recipient card; `fund` splits test
QOR with a cap and a floor. It also added `QORE_SECRETS_DIR`, so each
repository keeps its keys in its own directory. It ran each command on the
spike accounts (one 0.1 QOR transfer between two of them).

### 16 November 2026: the fUSD part of spike S2 (this worker)

**Owner and orchestrator:** 50 fUSD was sent from the auction deployer to
the spike owner account. The worker converted it to ERC-20, set fUSD limits
on the linked agent key, and relayed four agent calls: one allowed transfer,
one over the per-execution limit, one approval, and one over the daily limit.
Each result is recorded. 0.5 fUSD moved, to another spike account. The faucet
was not claimed with any scripted account.
