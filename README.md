# veedor

[![CI](https://github.com/JuanMarchetto/veedor/actions/workflows/ci.yml/badge.svg)](https://github.com/JuanMarchetto/veedor/actions/workflows/ci.yml)

Escrow that releases on proof.

AI agents can pay for anything. Nothing can prove they got what they paid for.

`veedor` is a settlement layer for agentic commerce: money locks against a
machine-readable job spec, and moves only when a verifier signs evidence bound to
that exact job, that exact spec, and that exact evidence. Built for physical work,
where the payment rail cannot see whether anything happened.

> A *veedor* was the crown officer who inspected weights, measures and quality
> before a shipment could be paid.

## See it settle, in 60 seconds

The fastest proof this is real, nothing to install:

- **Watch a job settle on devnet** (60s, narrated):
  [veedor-demo.mp4](https://github.com/JuanMarchetto/veedor/releases/download/v0.1.0-demo/veedor-demo.mp4)
- **The release transaction, on-chain:**
  [`5kjR36gG…`](https://explorer.solana.com/tx/5kjR36gGsGra7JTypHeQQovuLz39GhQ1H1soizkXxE1V1m7Qzr7CTCmpw714CgjDKUxttxBFG6VnSPu758RYUiZS?cluster=devnet)
  — 25 tokens left escrow and reached the provider after the ed25519 precompile cleared
  the verifier's signature.
- **The deployed program:** `8YpCfYtCBiLZ5SzTcmVZ5fkeBbPrvveWZnEzwpN8CQfJ`

Every claim in this README is runnable: [settle a job yourself](#on-devnet),
[run the 182 tests](#running-the-tests), [re-measure the market](research/x402-census).

## The gap this fills

Agent payment infrastructure shipped in the last year and works. OpenAI and Stripe
published the Agentic Commerce Protocol, Google published AP2, and Coinbase's x402
directory lists 24,929 services that take payment over HTTP. Read their specs and the
post-payment column is empty. Every one of them delegates fulfillment liability to the
merchant.

That directory is also the honest measure of how early this is. Sample it yourself —
the census script and the raw data it produced live in [`research/x402-census`](research/x402-census):

```sh
python3 research/x402-census/census.py --sample 1000
```

Across 1,000 of those services on 2026-07-20, the median price is one cent and 86%
charge under ten cents. They are API calls billed per request. The one physical thing
in the sample prints and mails paper letters; nothing else touches the world, and
nothing carries an acceptance criterion an inspection could check. Escrow
does not belong at that price, and nothing about an API call needs inspecting. This
project is built for the transactions that come after those: the ones where something
gets made, moved or delivered, and where the amount justifies checking.

That gap has consequences already. OpenAI shut down Instant Checkout in March 2026
citing fraud and tax operations. Marketplaces where agents hire humans verify
delivery with evidence self-reported by the party that gets paid.

Payment rails cannot close this themselves. Stripe absorbed fraud scoring because
it sees the transaction. Nobody on the rail can see whether a printed part matches
its tolerance, or whether a box arrived. That happens off-rail, and it needs a
neutral party holding the money.

## How it works

```
   job spec (hashed)            evidence bundle (hashed)
          |                              |
          v                              v
   [ Created ] --fund--> [ Funded ] --submit--> [ UnderReview ]
                             |                    |    |    |
                    no evidence, deadline    verifier |    buyer
                    passed: refund           signs    |    disputes
                                             |        |         |
                                    pass -> Released  |         v
                                    fail -> Refunded  |    [ Disputed ]
                                                      |     |        |
                              verifier silent past    |  arbiter   nobody
                              the window: Released ---+  rules     ruled:
                                                         |         Released
                                                pass -> Released
                                                fail -> Refunded
```

A verifier's signature covers `domain ‖ job_id ‖ spec_hash ‖ evidence_hash ‖ verdict`.
Change any field and the signature stops verifying, so an attestation cannot be
moved between jobs, specs, evidence or verdicts.

## Design decisions worth arguing with

These are product rules, not implementation details. They are enforced by tests.

**A failed inspection refunds the buyer.** Work that misses the spec does not get
paid, and does not sit frozen either.

**A silent verifier pays the provider.** The buyer already holds whatever was
delivered. Letting verifier silence hand them the work *and* the money is the wrong
incentive. The buyer has the entire review window to dispute.

**The arbiter is not the verifier.** Nobody rules on a complaint about their own
inspection. Their signatures live in separate domains, so neither can stand in for
the other. There is a test that replays a verifier attestation as an arbitration
ruling and requires it to fail.

**An absent arbiter cannot trap the money.** Disputes lapse to release. A frivolous
dispute buys delay, not a free refund. Charging for it needs a disputant bond,
which v0 does not have.

**The terms are immutable.** No sequence of events can change the amount, the
verifier, the arbiter or the spec mid-flight. This one is checked by a property
test over random event histories, not by an example.

**Whoever can afford to check the signature, checks it.** Verifying ed25519 costs more
than a Solana transaction is allowed to spend, so the on-chain program delegates to the
Ed25519 precompile. That raises the question of how the state machine tells an
authorized release from an unauthorized one when the check happens elsewhere. The
answer is a witness type: releasing takes a `VerifiedAttestation`, and the only ways to
get one are to verify the signature (what off-chain callers do) or to declare that a
trusted checker already did (what the program does, at the one line that sits right
after the precompile check). There is no third constructor, so no path reaches a
release without someone having verified. The state machine still enforces everything
else: a witness carries a verdict, not permission to skip the evidence on record or the
legal transition.

This design was forced, not chosen for looks. An earlier revision re-verified the
signature inside `Job::apply`, and that curve arithmetic alone blew past Solana's
1,400,000 CU ceiling: the genuinely-authorized release could not complete on real
hardware, even though every attack test still passed. The witness type is how the
authorized path got back under budget without opening a door for an unauthorized one.
The war story is in the header of `programs/settlement/tests/release_attacks.rs`.

**The machine never signs what it cannot measure.** An evidence bundle is written
by the party that gets paid, so a claim inside it is not a verification. Checks
that can be recomputed from an instrument reading (deviation against tolerance,
delivery time against deadline) settle automatically. Checks that cannot (does the
material match, is the count right) return `NeedsHumanJudgment`, the assessment
becomes `Inconclusive`, and the server refuses to sign and names the items a human
has to rule on. Reading the provider's own self-report and calling it a verdict
would rebuild the exact problem this project exists to fix.

## The verifier network

That last decision names the open question this project has to answer: in v0 the
measured value (`deviation_um = 40`) still arrives inside the bundle the provider
writes, so the program recomputes the comparison against the spec but not the
measurement. The comparison is independent; the measurement is not yet. Closing that
gap is the actual product, and here is the direction, so nobody mistakes the demo for
the whole thing.

**The verifier signs the raw reading, not the bundle.** A third party in the verifier
role takes the measurement, and their signature covers `domain ‖ job_id ‖ spec_hash ‖
reading` — the reading they took, not the one the provider declared. The program
already ties a signature to exactly one job and spec; what changes is whose signature
it is. Provider and verifier are held apart the same way arbiter and verifier already
are: separate signing domains, with a test that replays one as the other and requires
it to fail.

**The first verifiers already exist.** The marketplaces this is built for run
evidentiary arbitration by hand today: RentAHuman wrote it into its terms, and
pump.fun GO approves payouts at its own discretion. Those existing reviewers are the
verifier supply; veedor is the settlement rail their signature moves money on, not a
new inspection workforce to recruit.

**Collusion resistance scales with the money at stake.** Day one, the verifier is the
marketplace that already arbitrates, which has no incentive to collude against itself.
At scale, a verifier posts a bond that an arbitration reversal slashes, with the
existing dispute slot as the second instance. For checks a machine can recompute
(dimension against tolerance, delivery against deadline), an instrument with its own
key can sign the reading directly, which is where this is strongest and where the
provider never touches the number.

## Status

Early, and running on devnet. The state machine, the on-chain program and the agent
surfaces are in place, and the program is deployed. No mainnet, no real money.

| Component | State |
|---|---|
| `crates/settlement-core` — state machine, attestation, arbitration, timeouts | done, 46 tests |
| `crates/settlement-client` — canonical hashing, schema validation, signing, evidence evaluation | done, 54 tests |
| `services/mcp-settlement` — MCP tools an agent drives the job through | done, 17 tests |
| `spec/*.schema.json` — job spec and evidence formats | done |
| `programs/settlement` — Anchor shell: PDA accounts, SPL escrow, Ed25519 precompile checks | done, 34 tests |
| `demo` — drives one job through the deployed program on devnet | see below |
| `services/x402-gateway` — HTTP entry that answers 402 and takes payment | done, 31 tests (+2 devnet-only, `--ignored`). Real on-chain verification available, see below |

## On devnet

The program is deployed and executable:

```
8YpCfYtCBiLZ5SzTcmVZ5fkeBbPrvveWZnEzwpN8CQfJ
```

`cargo run -p demo` walks one job from creation to settlement against that
deployment: a real SPL mint, real token accounts, a real ed25519 precompile
verifying the verifier's signature, and real transactions. It prints an explorer
link for every step, so the claims here can be checked rather than believed.

Before you run it, the payer needs a funded devnet keypair (at least 0.1 SOL):

```sh
solana-keygen new                      # or point DEMO_KEYPAIR at an existing key
solana airdrop 1 --url devnet          # rate-limited? use faucet.solana.com
```

The demo reads `~/.config/solana/id.json` by default; set `DEMO_KEYPAIR=/path/to/key.json`
to use another. The first build compiles the Solana client crates, so expect a few
minutes once.

A run from 2026-07-20, with the job priced at 25.000000 of a six-decimal token:

| Step | State after | Transaction |
|---|---|---|
| `create_job` | `Created` | [`2FScXRTz…`](https://explorer.solana.com/tx/2FScXRTzv3cVywnPYPERMsqGfzDYdET5cDmdfNakew1TMNZuAd2j52dcxRMdef4zF2Z6Py36cXvuWovGkax7Af4K?cluster=devnet) |
| `fund` | `Funded`, escrow holds 25000000 | [`5gqyXVmc…`](https://explorer.solana.com/tx/5gqyXVmcw2iBgBimXMH4hCQ9Tw8U5dC1z2xSDMiPFAassJhY9XskgUpdSgB4xNduAMTyKSqsvuZ9ShNTJjdJr8bY?cluster=devnet) |
| `submit_evidence` | `UnderReview` | [`3DN6tqjY…`](https://explorer.solana.com/tx/3DN6tqjYPaFaZLmvRtdfVqWnpjWiHhfRhHx8azFTQ7cgdQKComiyfFGqMDcJhajVwSQX3arDevKvkAHUcaeRQuSM?cluster=devnet) |
| `release` | `Released`, provider holds 25000000 | [`5kjR36gG…`](https://explorer.solana.com/tx/5kjR36gGsGra7JTypHeQQovuLz39GhQ1H1soizkXxE1V1m7Qzr7CTCmpw714CgjDKUxttxBFG6VnSPu758RYUiZS?cluster=devnet) |

The job account for that run is
[`BQULDgfj…`](https://explorer.solana.com/address/BQULDgfj66yENxaPXaY1GMGneM9KPDpUF7FM7yP2GTU9?cluster=devnet).
What the verifier actually decided, printed by the same run:

```
Passed  'dims': measured deviation 40um against a 200um tolerance
Passed  'on_time': delivered at 1784552408, deadline was 1784556002
assessment Pass
```

Both acceptance items were recomputed from measurements. Had the spec asked whether
the material matched, the run would have stopped with `Inconclusive` instead of
signing, because no instrument settles that question.

## Try it from your own agent

The MCP server exposes the job cycle as tools, so any MCP client can drive one. Build
it and point a client at the binary:

```sh
cargo build --release -p mcp-settlement
claude mcp add veedor -- "$PWD/target/release/mcp-settlement"
```

For a client that takes JSON config:

```json
{
  "mcpServers": {
    "veedor": { "command": "/absolute/path/to/veedor/target/release/mcp-settlement" }
  }
}
```

Five tools: `create_job`, `job_status`, `submit_evidence`, `release`, `dispute`. Ask
your agent to create a job for a 3D printed part, submit evidence with a measured
deviation, and release it. Then ask it to do the same with an acceptance item the
machine cannot measure, and watch the server refuse to sign.

Here is that second case, printed by the binary. The spec asks for a measurable check
and an unmeasurable one, the provider vouches for the unmeasurable one in its own
evidence, and the server declines:

```
ok       {"job_id":"81a3036a…","spec_hash":"7c29edba…","state":"Funded"}
ok       {"evidence_hash":"3a69f895…","state":"UnderReview"}
REFUSED  cannot sign automatically: 1 acceptance item(s) need a human verifier (mat).
         No instrument settles these, and the evidence bundle is written by the party
         that gets paid.
```

The job stays open for a human verifier instead of settling on the provider's word.

This v0 keeps state in memory and holds the verifier key itself, which is the right
shape for trying the flow and the wrong shape for anything else.

## Running the tests

```sh
cargo test --workspace
```

182 tests. Most of the time goes to one test that flips all 512 bits of a signature and
requires every single one to break the release.

Two more tests exist but do not run by default: `services/x402-gateway`'s
`tests/payment_verification_solana.rs` has two `#[ignore]`d tests that create a real
SPL mint and submit a real transfer on devnet to prove `SolanaPaymentVerifier`
accepts a genuine payment and rejects a replay of it. Run them explicitly:

```sh
cargo test -p x402-gateway --test payment_verification_solana -- --ignored --test-threads=1
```

The Anchor program's tests run against `litesvm`, an in-process SVM with the real
ed25519 precompile, so the attack tests carry genuine signatures rather than mocks. They
prove the program ties the precompile's output to the exact expected key and message, not
merely that some precompile ran. Concretely: a cryptographically valid signature from the
*wrong-role* key (the arbiter, a real signer of this job) is rejected
(`release_where_the_precompile_verifies_the_wrong_key_is_rejected`); a valid signature
over a *ruling-domain* message with the identical job, spec, evidence and verdict is
rejected as an attestation (`release_where_the_precompile_verifies_a_ruling_message_instead_of_an_attestation_is_rejected`);
and a precompile instruction placed *after* the settle instead of before is rejected
(`release_with_the_precompile_ix_after_instead_of_before_is_rejected`). Build the program
first:

```sh
cargo build-sbf --manifest-path programs/settlement/Cargo.toml
```

The state machine carries no Solana dependency on purpose: the logic that decides
whether money moves runs in microseconds, so property tests can hammer it with
random event histories, and a Kani harness can check it exhaustively.

The invariant suite was checked by injecting a real bug (letting a settled job
accept funds again) and confirming the properties caught it. A property test you
have never seen fail is decoration.

### Formal verification

`crates/settlement-core/src/proofs.rs` holds [Kani](https://github.com/model-checking/kani)
harnesses for `Job::apply`. Property tests sample random event histories; Kani proves the same
claims for every input, not a sample of them. This is possible because `apply` no longer touches
ed25519: signature checks happen upstream, in `Attestation::verify_for` and
`Ruling::verify_for`, before an event ever reaches `apply`. What's left is integer comparisons
and struct rebuilds, a shape a model checker can decide instead of sample.

Install Kani once (`cargo install --locked kani-verifier && cargo kani setup`), then run:

```sh
cargo kani --manifest-path crates/settlement-core/Cargo.toml -j --output-format=terse
```

`-j` checks the 9 harnesses in parallel (it requires `--output-format=terse` on current
Kani); the whole run finishes in about 30 seconds on a 4-core machine. Drop both flags
to run them one at a time (about 2 minutes total) with full per-harness output. Every harness reports `VERIFICATION:- SUCCESSFUL`:

- **Absorbency.** `Released` and `Refunded` reject every event, for every `now`.
- **Monotonicity.** A successful transition never lowers the state's rank
  (`Created < Funded < UnderReview < Disputed < settled`).
- **Immutable terms.** No successful transition changes `job_id`, `spec_hash`, `amount`,
  `verifier`, `arbiter`, or `windows`.
- **Payment requires evidence.** `next.state == Released` implies `evidence_hash.is_some()` and
  the prior state was `UnderReview` or `Disputed`.
- **Evidence is write-once.** Once `evidence_hash` is `Some(h)`, no successful transition changes
  it.
- **Deadline arithmetic never overflows.** The `saturating_add` behind `review_deadline` and
  `arbitration_deadline` matches its spec for every `i64` pair, `now == i64::MAX` and maximal
  windows included.

The last two of those hold only for jobs reachable from `Job::created`, not for an arbitrary
`Job` value. Kani found this the hard way: an arbitrary `Job { state: UnderReview,
evidence_hash: None }` is not a state any real history reaches (the only transition into
`UnderReview` always sets `evidence_hash`), but `apply` does not independently check for it, so
the first version of the payment-requires-evidence harness failed on exactly that input, and
evidence-write-once failed the mirror case in `Funded`. The fix is not a narrower harness: two
more harnesses (`well_formed_base_case`, `well_formed_is_inductive`) prove by induction that
every job reachable from `Job::created` keeps evidence and state in that relationship, and the
two affected harnesses assume that proven invariant instead of guessing at the input. That
`kani::assume` is the only one in the file; everywhere else, harnesses run over the full type,
not a reachable subset of it.

## What is not real yet

**The x402 gateway can now verify a real on-chain payment, with no facilitator.**
`SolanaPaymentVerifier` (`services/x402-gateway/src/verifier.rs`) decodes a signed
Solana transaction out of the payment proof, checks its signatures cryptographically,
scans it for an exact `TransferChecked` to the configured recipient's associated
token account (right mint, right amount, no "at least") and confirms via RPC that the
transaction's own signature is actually landed on devnet with no error. Two tests
prove this against real devnet, not a mock: `cargo test -p x402-gateway --test
payment_verification_solana -- --ignored --test-threads=1` creates a real SPL mint
and submits a real transfer, then shows the gateway accepts it once and rejects the
identical transaction presented a second time.

The `StubVerifier` this replaced still exists, still runs by default when the gateway
binary is started with no `X402_GATEWAY_RPC_URL` set, and still only checks *authorization*
(an ed25519 signature over the (spec, amount, asset, destination) tuple) rather than a
real payment -- it exists now to exercise the HTTP layer in tests without a chain, not
because on-chain verification is unbuilt.

What `SolanaPaymentVerifier` genuinely does not do, so nobody mistakes v0 for more
than it is:

- **No facilitator, and no gateway-as-fee-payer, by design.** The model it chose is
  the payer signs and submits their own transaction, then presents it as proof; the
  gateway confirms it already happened rather than broadcasting it. See that type's
  doc comment for why this is the model, not a corner cut.
- **No spec binding.** Nothing ties a specific transfer to a specific job spec the
  way `StubVerifier`'s nonce does. Replay is blocked globally (one transaction funds
  at most one job, ever), but two different specs that happen to require the
  identical (amount, asset, payTo) triple could both be satisfied by presenting the
  same transaction — whichever `POST /jobs` gets there first wins, and the second
  gets `payment_already_used`, not a spec-specific rejection.
- **Classic SPL Token only.** Token-2022 mints are out of scope.
- **Legacy transactions only.** `VersionedTransaction` is not decoded.
- **In-memory replay protection.** The set of used transaction signatures does not
  survive a gateway restart, same as every other piece of state this v0 keeps.

**The measured values are still provider-authored in v0.** The evidence bundle is
written by the party that gets paid, and the verifier recomputes checks from the
readings inside it: the comparison is independent, the measurement is not yet. The
missing piece is the verifier who holds the instrument and signs the raw reading,
and that network is the thing this project exists to build.

**Devnet is not mainnet.** The program is deployed, the demo settles a real job, the
gateway can verify a real devnet payment, and none of it involves money anyone can
lose.

## License

Apache-2.0
