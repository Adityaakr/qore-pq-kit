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
