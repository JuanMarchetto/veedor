//! Formal verification harnesses for [`Job::apply`] (Kani / CBMC).
//!
//! `Job::apply` no longer touches ed25519: signature checks live upstream, in
//! [`Attestation::verify_for`] and [`Ruling::verify_for`]. Every event that reaches `apply`
//! already carries an unsigned witness ([`VerifiedAttestation`] / [`VerifiedRuling`]), built
//! either by those two functions or by `trusting_external_check` for callers (the Solana
//! program) that delegated the check to the Ed25519 precompile. That makes `apply` itself
//! nothing but integer comparisons and struct rebuilds over `i64`/`u64`/`[u8; 32]` fields, with
//! no loops and no curve arithmetic: exactly the shape Kani can decide exhaustively instead of
//! by sampling.
//!
//! Most harnesses below quantify over the FULL domain of their inputs: an arbitrary `Job` with
//! every field independent, not just the ones `Job::created` plus a legal history could produce.
//! Two properties (`released` implies evidence-on-record, and evidence being write-once) are
//! only true of REACHABLE jobs: Kani found real counterexamples of the form `Job { state:
//! UnderReview, evidence_hash: None, .. }`, a value no sequence of `apply` calls starting from
//! `Job::created` can ever produce (the only transition into `UnderReview` always sets
//! `evidence_hash` to `Some`), but one `apply` itself does not independently re-check before
//! trusting it. See "Reachability" below for how those two harnesses are scoped to reachable
//! jobs, and for the one and only `kani::assume` in this file. Every other harness narrows
//! nothing: where a harness fixes the `Event` *shape* (e.g. always `Event::SubmitEvidence`) to
//! target one match arm of `apply`, every field inside that event is still fully arbitrary, and
//! the harness still explores every `Job` (including every other state), relying on `apply`'s
//! own match to reject the ones where that arm does not apply. If Kani ever cannot finish a
//! harness as written, that will be called out explicitly in the harness's doc comment and in
//! the verification report, not silently narrowed.
//!
//! ## Reachability
//!
//! `well_formed` below is a structural invariant: `state ∈ {Created, Funded} ⇒ evidence_hash ==
//! None`, and `state ∈ {UnderReview, Disputed, Released} ⇒ evidence_hash.is_some()`. It is
//! proved by induction, the standard way to turn "true for every job reachable by an unbounded
//! number of `apply` calls" into something a single bounded-but-exhaustive Kani harness can
//! check:
//!
//!   - `well_formed_base_case`: `Job::created(..)` satisfies it, for every choice of arguments.
//!   - `well_formed_is_inductive`: for an arbitrary job that already satisfies it, every
//!     successful `apply` produces a job that still satisfies it, for every event and `now`.
//!
//! Those two together mean `well_formed` holds after `Job::created` and after any subsequent
//! sequence of successful `apply` calls, however long: exactly the set of jobs the property
//! tests in `tests/invariants.rs` build (they too only ever start from `created()` and fold
//! `apply` over a random history). `released_requires_evidence_and_a_review_predecessor` and
//! `evidence_is_write_once` open with `kani::assume(well_formed(&job))`, which is sound only
//! because those two harnesses exist and pass; it is not a shortcut to make a harness terminate
//! faster; it is what makes "for any job" mean "for any job this state machine can actually
//! reach" instead of "for any 41-byte struct with these types." This is the only `kani::assume`
//! in this file.
//!
//! Run with `cargo kani --manifest-path crates/settlement-core/Cargo.toml` from the repo root,
//! or see the README's "Running the tests" section.

#![cfg(kani)]

use crate::{Event, Job, State, Verdict, VerifiedAttestation, VerifiedRuling, Windows};

// ---------------------------------------------------------------------------------------------
// Arbitrary-value builders.
//
// These are hand-rolled instead of `#[derive(kani::Arbitrary)]` on the public types in `lib.rs`,
// so the production API carries no Kani-specific code at all: this whole file, builders
// included, disappears outside `cargo kani` via `#![cfg(kani)]` above.
// ---------------------------------------------------------------------------------------------

fn any_bytes32() -> [u8; 32] {
    // Written as a literal instead of a loop so there is no unwind bound to justify: this is
    // straight-line code, 32 independent symbolic bytes, fully exhaustive over [u8; 32].
    [
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    ]
}

fn any_option_bytes32() -> Option<[u8; 32]> {
    if kani::any() {
        Some(any_bytes32())
    } else {
        None
    }
}

fn any_option_i64() -> Option<i64> {
    if kani::any() {
        Some(kani::any())
    } else {
        None
    }
}

fn any_verdict() -> Verdict {
    if kani::any() { Verdict::Pass } else { Verdict::Fail }
}

/// One of the 6 `State` variants, chosen by a symbolic `u8 % 6`. `%6` is total (no `assume`
/// needed) and surjective onto `0..6` over `u8`'s range, so every variant remains reachable.
fn any_state() -> State {
    match kani::any::<u8>() % 6 {
        0 => State::Created,
        1 => State::Funded,
        2 => State::UnderReview,
        3 => State::Disputed,
        4 => State::Released,
        _ => State::Refunded,
    }
}

fn any_windows() -> Windows {
    Windows { evidence_deadline: kani::any(), review: kani::any(), arbitration: kani::any() }
}

/// A `Job` with every field arbitrary, `state` included. Same shape as what `apply` would see
/// if it were called on an account deserialized from arbitrary bytes: nothing here assumes the
/// job is one `apply` could actually have produced from `Job::created`, which is the point —
/// these harnesses hold even for a state no legal history reaches.
fn any_job() -> Job {
    Job {
        job_id: any_bytes32(),
        state: any_state(),
        spec_hash: any_bytes32(),
        amount: kani::any(),
        verifier: any_bytes32(),
        arbiter: any_bytes32(),
        evidence_hash: any_option_bytes32(),
        windows: any_windows(),
        review_deadline: any_option_i64(),
        arbitration_deadline: any_option_i64(),
    }
}

/// One of the 6 `Event` variants, chosen by a symbolic `u8 % 6`, each carrying fully arbitrary
/// payload fields. Total and surjective onto all 6 variants for the same reason as `any_state`.
fn any_event() -> Event {
    match kani::any::<u8>() % 6 {
        0 => Event::Fund,
        1 => Event::SubmitEvidence { evidence_hash: any_bytes32() },
        2 => Event::Release {
            attestation: VerifiedAttestation::trusting_external_check(
                any_bytes32(),
                any_verdict(),
            ),
        },
        3 => Event::Dispute,
        4 => Event::Resolve {
            ruling: VerifiedRuling::trusting_external_check(any_bytes32(), any_verdict()),
        },
        _ => Event::Timeout,
    }
}

/// `saturating_add`'s spec, computed with an intermediate `i128` so this oracle itself cannot
/// overflow. Independent of the `saturating_add` call inside `Job::apply`: this is what the
/// deadline math is being checked against, not a restatement of it.
fn saturating_add_oracle(a: i64, b: i64) -> i64 {
    let sum = a as i128 + b as i128;
    if sum > i64::MAX as i128 {
        i64::MAX
    } else if sum < i64::MIN as i128 {
        i64::MIN
    } else {
        sum as i64
    }
}

/// Rank used by the property tests in `tests/invariants.rs`, duplicated here so this file has
/// no `#[cfg(test)]` dependency on that crate-external module.
fn rank(state: State) -> u8 {
    match state {
        State::Created => 0,
        State::Funded => 1,
        State::UnderReview => 2,
        State::Disputed => 3,
        State::Released | State::Refunded => 4,
    }
}

/// Structural invariant proved-by-induction in `well_formed_base_case` +
/// `well_formed_is_inductive`. See the "Reachability" section of the module doc comment: this
/// holds for exactly the jobs reachable from `Job::created` by zero or more successful `apply`
/// calls, no more and no less.
///
/// `Refunded` is deliberately unconstrained: it is reached either with evidence (a verifier or
/// arbiter failed the work) or without it (the provider never submitted before the evidence
/// deadline), so no fixed relationship holds there.
fn well_formed(job: &Job) -> bool {
    match job.state {
        State::Created | State::Funded => job.evidence_hash.is_none(),
        State::UnderReview | State::Disputed | State::Released => job.evidence_hash.is_some(),
        State::Refunded => true,
    }
}

// ---------------------------------------------------------------------------------------------
// 1. Absorbency: Released and Refunded accept nothing.
// ---------------------------------------------------------------------------------------------

/// From `State::Released` or `State::Refunded`, no event and no `now` produces `Ok`. Every other
/// field of `Job` (including `evidence_hash`, both deadlines, and the deal terms) is fully
/// arbitrary; only `state` is pinned, and only to the two terminal values under test.
#[kani::proof]
fn absorbing_terminal_states_reject_everything() {
    let mut job = any_job();
    job.state = if kani::any() { State::Released } else { State::Refunded };

    let event = any_event();
    let now: i64 = kani::any();

    assert!(job.apply(event, now).is_err(), "a terminal state accepted an event");
}

// ---------------------------------------------------------------------------------------------
// 2. Monotonicity: rank never decreases on a successful transition.
// ---------------------------------------------------------------------------------------------

#[kani::proof]
fn rank_never_decreases_on_success() {
    let job = any_job();
    let event = any_event();
    let now: i64 = kani::any();

    if let Ok(next) = job.apply(event, now) {
        assert!(rank(next.state) >= rank(job.state), "state rank went backwards");
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Immutable terms.
// ---------------------------------------------------------------------------------------------

#[kani::proof]
fn terms_are_immutable_on_success() {
    let job = any_job();
    let event = any_event();
    let now: i64 = kani::any();

    if let Ok(next) = job.apply(event, now) {
        assert_eq!(next.job_id, job.job_id, "job_id changed");
        assert_eq!(next.spec_hash, job.spec_hash, "spec_hash changed");
        assert_eq!(next.amount, job.amount, "amount changed");
        assert_eq!(next.verifier, job.verifier, "verifier changed");
        assert_eq!(next.arbiter, job.arbiter, "arbiter changed");
        assert_eq!(next.windows, job.windows, "windows changed");
    }
}

// ---------------------------------------------------------------------------------------------
// Reachability: `well_formed` proved by induction. See the module doc comment. These two
// harnesses are what justify the one `kani::assume` in this file, used below in harnesses 4
// and 5.
// ---------------------------------------------------------------------------------------------

/// Base case: whatever `Job::created` is handed, the job it returns is well-formed.
#[kani::proof]
fn well_formed_base_case() {
    let job_id = any_bytes32();
    let spec_hash = any_bytes32();
    let amount: u64 = kani::any();
    let verifier = any_bytes32();
    let arbiter = any_bytes32();
    let windows = any_windows();

    let job = Job::created(job_id, spec_hash, amount, verifier, arbiter, windows);
    assert!(well_formed(&job), "Job::created is not well-formed");
}

/// Inductive step: starting from ANY well-formed job (not just ones `Job::created` could have
/// produced directly, since induction lets later steps build on earlier ones), every successful
/// `apply` over every event and every `now` produces a job that is still well-formed.
#[kani::proof]
fn well_formed_is_inductive() {
    let job = any_job();
    kani::assume(well_formed(&job));

    let event = any_event();
    let now: i64 = kani::any();

    if let Ok(next) = job.apply(event, now) {
        assert!(well_formed(&next), "apply broke the well-formedness invariant");
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Payment requires evidence, out of a review-shaped state.
//
// True only for reachable jobs: an arbitrary `Job { state: UnderReview, evidence_hash: None }`
// (unreachable, but not ruled out by `apply` itself) lets `(UnderReview, Timeout)` release
// with no evidence on record, since that arm copies `evidence_hash` through from `self`
// unchanged instead of re-checking it. `well_formed_is_inductive` above is what makes assuming
// it away sound rather than a scope cut.
// ---------------------------------------------------------------------------------------------

#[kani::proof]
fn released_requires_evidence_and_a_review_predecessor() {
    let job = any_job();
    kani::assume(well_formed(&job));

    let event = any_event();
    let now: i64 = kani::any();

    let before_state = job.state;
    if let Ok(next) = job.apply(event, now) {
        if next.state == State::Released {
            assert!(next.evidence_hash.is_some(), "released without evidence on record");
            assert!(
                matches!(before_state, State::UnderReview | State::Disputed),
                "paid straight out of {:?}",
                before_state
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 5. Evidence is write-once.
//
// True only for reachable jobs, for the mirror-image reason to harness 4: an arbitrary
// `Job { state: Funded, evidence_hash: Some(h) }` (unreachable: well-formed `Funded` always
// carries `None`) lets `(Funded, SubmitEvidence)` legally overwrite `h` with the event's own
// evidence_hash, since that arm's job is to SET evidence_hash, not to check it was unset.
// ---------------------------------------------------------------------------------------------

#[kani::proof]
fn evidence_is_write_once() {
    let mut job = any_job();
    let recorded = any_bytes32();
    job.evidence_hash = Some(recorded);
    kani::assume(well_formed(&job));

    let event = any_event();
    let now: i64 = kani::any();

    if let Ok(next) = job.apply(event, now) {
        assert_eq!(next.evidence_hash, Some(recorded), "evidence_hash was overwritten");
    }
}

// ---------------------------------------------------------------------------------------------
// 6. Deadline arithmetic: no panic, no wraparound, matches the saturating spec exactly.
//
// `job.windows.review`/`.arbitration` and `now` are both fully arbitrary i64, so this already
// covers `now == i64::MAX` together with the largest possible window in the same sweep that
// covers every other value; there is no separate "extreme" harness because there is nothing
// left outside the domain these two already explore.
// ---------------------------------------------------------------------------------------------

/// Only `(State::Funded, Event::SubmitEvidence)` computes `review_deadline`; every other
/// `(state, event)` combination for this fixed event shape falls through to
/// `Error::IllegalTransition` before touching the arithmetic, so pinning the event to
/// `SubmitEvidence` while leaving `job` (state included) fully arbitrary still exercises the
/// full input domain of the one branch that matters.
#[kani::proof]
fn review_deadline_matches_saturating_spec() {
    let job = any_job();
    let evidence_hash = any_bytes32();
    let now: i64 = kani::any();

    if let Ok(next) = job.apply(Event::SubmitEvidence { evidence_hash }, now) {
        let expected = saturating_add_oracle(now, job.windows.review);
        assert_eq!(next.review_deadline, Some(expected), "review_deadline diverged from spec");
    }
}

/// Same reasoning as above for `(State::UnderReview, Event::Dispute)`, the only arm that
/// computes `arbitration_deadline`.
#[kani::proof]
fn arbitration_deadline_matches_saturating_spec() {
    let job = any_job();
    let now: i64 = kani::any();

    if let Ok(next) = job.apply(Event::Dispute, now) {
        let expected = saturating_add_oracle(now, job.windows.arbitration);
        assert_eq!(
            next.arbitration_deadline,
            Some(expected),
            "arbitration_deadline diverged from spec"
        );
    }
}
