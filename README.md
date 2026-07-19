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

## Status

Early. The state machine is done and tested. The on-chain program and the agent
surfaces are in progress.

| Component | State |
|---|---|
| `crates/settlement-core` — state machine, attestation, arbitration, timeouts | done, 38 tests |
| `spec/*.schema.json` — job spec and evidence formats | done |
| Anchor program (accounts, token movement, Ed25519 precompile checks) | in progress |
| Agent surfaces (MCP tools, x402 entry) | in progress |
| Devnet demo | not yet |

## Running the tests

```sh
cargo test -p settlement-core
```

Under 30 seconds. Most of it is one test that flips all 512 bits of a signature and
requires every single one to break the release.

The state machine carries no Solana dependency on purpose: the logic that decides
whether money moves runs in microseconds, so property tests can hammer it with
random event histories, and a proof harness can reach it later.

The invariant suite was checked by injecting a real bug (letting a settled job
accept funds again) and confirming the properties caught it. A property test you
have never seen fail is decoration.

## License

Apache-2.0
