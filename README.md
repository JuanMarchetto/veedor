# veedor

Escrow that releases on proof.

AI agents can pay for anything. Nothing can prove they got what they paid for.

`veedor` is a settlement layer for agentic commerce: money locks against a
machine-readable job spec, and moves only when a verifier signs evidence bound to
that exact job, that exact spec, and that exact evidence. Built for physical work,
where the payment rail cannot see whether anything happened.

> A *veedor* was the crown officer who inspected weights, measures and quality
> before a shipment could be paid.

## The gap this fills

Agent payment infrastructure shipped in the last year and works: x402 processed
165M transactions, OpenAI and Stripe published the Agentic Commerce Protocol,
Google published AP2. Read their specs and the post-payment column is empty. Every
one of them delegates fulfillment liability to the merchant.

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

**The machine never signs what it cannot measure.** An evidence bundle is written
by the party that gets paid, so a claim inside it is not a verification. Checks
that can be recomputed from an instrument reading (deviation against tolerance,
delivery time against deadline) settle automatically. Checks that cannot (does the
material match, is the count right) return `NeedsHumanJudgment`, the assessment
becomes `Inconclusive`, and the server refuses to sign and names the items a human
has to rule on. Reading the provider's own self-report and calling it a verdict
would rebuild the exact problem this project exists to fix.

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
| x402 payment entry | in progress |

## On devnet

The program is deployed and executable:

```
8YpCfYtCBiLZ5SzTcmVZ5fkeBbPrvveWZnEzwpN8CQfJ
```

`cargo run -p demo` walks one job from creation to settlement against that
deployment: a real SPL mint, real token accounts, a real ed25519 precompile
verifying the verifier's signature, and real transactions. It prints an explorer
link for every step, so the claims here can be checked rather than believed.

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

## Running the tests

```sh
cargo test
```

151 tests. Most of the time goes to one test that flips all 512 bits of a signature and
requires every single one to break the release.

The Anchor program's tests run against `litesvm`, an in-process SVM with the real
ed25519 precompile, so the attack tests carry genuine signatures and prove the program
ties the precompile's output to the exact expected key and message rather than trusting
that some precompile ran. Build the program first:

```sh
cargo build-sbf --manifest-path programs/settlement/Cargo.toml
```

The state machine carries no Solana dependency on purpose: the logic that decides
whether money moves runs in microseconds, so property tests can hammer it with
random event histories, and a proof harness can reach it later.

The invariant suite was checked by injecting a real bug (letting a settled job
accept funds again) and confirming the properties caught it. A property test you
have never seen fail is decoration.

## License

Apache-2.0
