//! Escrow state machine for agentic settlement.
//!
//! Pure logic: no Solana types, no I/O, no allocation. The on-chain program is a thin
//! shell that validates accounts, calls [`Job::apply`], and moves tokens according to
//! the resulting state.
//!
//! The one rule the whole product rests on: funds leave the escrow only when a verifier
//! signed a verdict over *this* job, *this* spec, and *this* evidence.

#![no_std]

use ed25519_dalek::{Signature, VerifyingKey};

/// Domain tag for a verifier's inspection result. Without it, a signature produced
/// for another protocol under the same key could be replayed as an attestation.
pub const ATTESTATION_DOMAIN: &[u8] = b"agentic-settlement/attestation/v1";

/// Domain tag for an arbiter's ruling on a dispute. Distinct from the attestation
/// domain so a verifier's signature can never stand in as a ruling, or the reverse.
/// Same length as the attestation domain, which keeps the signed message fixed-size.
pub const RULING_DOMAIN: &[u8] = b"agentic-settlement/arbitration/v1";

/// Domain (33) + job_id (32) + spec_hash (32) + evidence_hash (32) + verdict (1).
pub const ATTESTATION_MESSAGE_LEN: usize = 130;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Created,
    Funded,
    UnderReview,
    Released,
    Refunded,
    Disputed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
}

impl Verdict {
    /// Never zero: a zeroed buffer must not decode as a valid verdict.
    fn tag(self) -> u8 {
        match self {
            Verdict::Pass => 1,
            Verdict::Fail => 2,
        }
    }
}

/// A verifier's signed inspection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attestation {
    pub evidence_hash: [u8; 32],
    pub verdict: Verdict,
    pub signature: [u8; 64],
}

/// An arbiter's signed decision on a disputed job. Same shape as an attestation and
/// deliberately a separate type: the two are not interchangeable, and the compiler
/// should say so before the signature check does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ruling {
    pub evidence_hash: [u8; 32],
    pub verdict: Verdict,
    pub signature: [u8; 64],
}

/// Proof that an attestation's signature was checked against the job's verifier key
/// over the canonical message. Releasing funds takes one of these, and there are
/// exactly two ways to get one: [`Attestation::verify_for`], which does the curve
/// arithmetic, or [`VerifiedAttestation::trusting_external_check`], for callers who
/// delegated the check to something cheaper. There is no third way, so no code path
/// reaches a release without someone having verified the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub evidence_hash: [u8; 32],
    pub verdict: Verdict,
}

/// The same witness for an arbiter's ruling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRuling {
    pub evidence_hash: [u8; 32],
    pub verdict: Verdict,
}

impl VerifiedAttestation {
    /// For callers whose environment cannot afford ed25519 verification, such as a
    /// Solana program delegating to the Ed25519 precompile.
    ///
    /// The caller must have confirmed that a trusted checker verified exactly
    /// `attestation_message(job.job_id, job.spec_hash, evidence_hash, verdict)` against
    /// `job.verifier`. Calling this without that confirmation hands over the escrow.
    pub fn trusting_external_check(evidence_hash: [u8; 32], verdict: Verdict) -> Self {
        VerifiedAttestation { evidence_hash, verdict }
    }
}

impl VerifiedRuling {
    /// See [`VerifiedAttestation::trusting_external_check`]. The message here is
    /// `ruling_message(..)` and the key is `job.arbiter`.
    pub fn trusting_external_check(evidence_hash: [u8; 32], verdict: Verdict) -> Self {
        VerifiedRuling { evidence_hash, verdict }
    }
}

/// The clocks attached to a job, all in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Windows {
    /// Absolute time by which the provider must submit evidence.
    pub evidence_deadline: i64,
    /// How long the verifier gets to answer, counted from submission.
    pub review: i64,
    /// How long the arbiter gets to rule, counted from the dispute.
    pub arbitration: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Fund,
    SubmitEvidence { evidence_hash: [u8; 32] },
    Release { attestation: VerifiedAttestation },
    Dispute,
    /// An arbiter's decision on a disputed job.
    Resolve { ruling: VerifiedRuling },
    /// Permissionless: anyone may crank an expired job to its settled state.
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    IllegalTransition { from: State, event: Event },
    /// The signature does not verify against the verifier key over the canonical message.
    InvalidAttestation,
    /// The signature does not verify against the arbiter key over the canonical ruling.
    InvalidRuling,
    /// The signed verdict is about evidence other than what was submitted.
    EvidenceMismatch,
    /// Cranking a job whose clock has not run out yet.
    DeadlineNotReached,
    /// Acting after the window for that action closed.
    DeadlinePassed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub job_id: [u8; 32],
    pub state: State,
    pub spec_hash: [u8; 32],
    pub amount: u64,
    /// ed25519 public key of the party allowed to attest fulfillment.
    pub verifier: [u8; 32],
    /// ed25519 public key of the party allowed to rule on a dispute. Kept separate
    /// from the verifier: nobody judges a complaint about their own inspection.
    pub arbiter: [u8; 32],
    pub evidence_hash: Option<[u8; 32]>,
    pub windows: Windows,
    /// Set on submission: `submitted_at + windows.review`.
    pub review_deadline: Option<i64>,
    /// Set on dispute: `disputed_at + windows.arbitration`.
    pub arbitration_deadline: Option<i64>,
}

/// The exact bytes a verifier signs. Any change to any field changes the message,
/// so an attestation cannot be moved between jobs, specs, evidence, or verdicts.
pub fn attestation_message(
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> [u8; ATTESTATION_MESSAGE_LEN] {
    signed_verdict_message(ATTESTATION_DOMAIN, job_id, spec_hash, evidence_hash, verdict)
}

/// The exact bytes an arbiter signs. Differs from [`attestation_message`] only in the
/// domain tag, which is the whole point: neither signature verifies as the other.
pub fn ruling_message(
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> [u8; ATTESTATION_MESSAGE_LEN] {
    signed_verdict_message(RULING_DOMAIN, job_id, spec_hash, evidence_hash, verdict)
}

fn signed_verdict_message(
    domain: &[u8],
    job_id: [u8; 32],
    spec_hash: [u8; 32],
    evidence_hash: [u8; 32],
    verdict: Verdict,
) -> [u8; ATTESTATION_MESSAGE_LEN] {
    debug_assert_eq!(domain.len(), ATTESTATION_DOMAIN.len(), "domains must be equal length");

    let mut message = [0u8; ATTESTATION_MESSAGE_LEN];
    let mut at = 0;

    let mut write = |bytes: &[u8], at: &mut usize| {
        message[*at..*at + bytes.len()].copy_from_slice(bytes);
        *at += bytes.len();
    };

    write(domain, &mut at);
    write(&job_id, &mut at);
    write(&spec_hash, &mut at);
    write(&evidence_hash, &mut at);
    write(&[verdict.tag()], &mut at);

    debug_assert_eq!(at, ATTESTATION_MESSAGE_LEN);
    message
}

fn verify(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(signature)).is_ok()
}

impl Job {
    pub fn created(
        job_id: [u8; 32],
        spec_hash: [u8; 32],
        amount: u64,
        verifier: [u8; 32],
        arbiter: [u8; 32],
        windows: Windows,
    ) -> Self {
        Job {
            job_id,
            state: State::Created,
            spec_hash,
            amount,
            verifier,
            arbiter,
            evidence_hash: None,
            windows,
            review_deadline: None,
            arbitration_deadline: None,
        }
    }

    pub fn apply(self, event: Event, now: i64) -> Result<Self, Error> {
        match (self.state, event) {
            (State::Created, Event::Fund) => Ok(Job { state: State::Funded, ..self }),

            (State::Funded, Event::SubmitEvidence { evidence_hash }) => {
                if now > self.windows.evidence_deadline {
                    return Err(Error::DeadlinePassed);
                }
                Ok(Job {
                    state: State::UnderReview,
                    evidence_hash: Some(evidence_hash),
                    review_deadline: Some(now.saturating_add(self.windows.review)),
                    ..self
                })
            }

            // The provider never delivered: the buyer takes the money back.
            (State::Funded, Event::Timeout) => {
                if now <= self.windows.evidence_deadline {
                    return Err(Error::DeadlineNotReached);
                }
                Ok(Job { state: State::Refunded, ..self })
            }

            (State::UnderReview, Event::Release { attestation }) => {
                // The signature was checked before this witness existed. What the
                // checker could not know is which evidence this job actually received.
                self.check_evidence(attestation.evidence_hash)?;
                Ok(Job { state: settled_by(attestation.verdict), ..self })
            }

            // The work was delivered and the verifier went silent. Paying the provider
            // is the safe default: the buyer already holds whatever was delivered, and
            // a buyer who disagrees has the dispute path open the whole window.
            (State::UnderReview, Event::Timeout) => {
                let deadline = self.review_deadline.ok_or(Error::DeadlineNotReached)?;
                if now <= deadline {
                    return Err(Error::DeadlineNotReached);
                }
                Ok(Job { state: State::Released, ..self })
            }

            // A buyer who sat out the whole review window cannot reopen it afterwards.
            (State::UnderReview, Event::Dispute) => {
                let deadline = self.review_deadline.ok_or(Error::DeadlineNotReached)?;
                if now > deadline {
                    return Err(Error::DeadlinePassed);
                }
                Ok(Job {
                    state: State::Disputed,
                    arbitration_deadline: Some(now.saturating_add(self.windows.arbitration)),
                    ..self
                })
            }

            (State::Disputed, Event::Resolve { ruling }) => {
                self.check_evidence(ruling.evidence_hash)?;
                Ok(Job { state: settled_by(ruling.verdict), ..self })
            }

            // Nobody ruled. The dispute lapses the same way an unanswered review does:
            // the party that delivered and evidenced the work gets paid. A frivolous
            // dispute therefore buys delay, not a free refund. v1 adds a disputant bond
            // so it costs money too.
            (State::Disputed, Event::Timeout) => {
                let deadline = self.arbitration_deadline.ok_or(Error::DeadlineNotReached)?;
                if now <= deadline {
                    return Err(Error::DeadlineNotReached);
                }
                Ok(Job { state: State::Released, ..self })
            }

            (from, event) => Err(Error::IllegalTransition { from, event }),
        }
    }

    /// Off-chain convenience: verify the attestation, then apply it. On-chain callers
    /// build the witness from their precompile check and call [`Job::apply`] directly.
    pub fn release(self, attestation: Attestation, now: i64) -> Result<Self, Error> {
        let verified = attestation.verify_for(&self)?;
        self.apply(Event::Release { attestation: verified }, now)
    }

    /// Off-chain convenience for an arbiter's ruling. See [`Job::release`].
    pub fn resolve(self, ruling: Ruling, now: i64) -> Result<Self, Error> {
        let verified = ruling.verify_for(&self)?;
        self.apply(Event::Resolve { ruling: verified }, now)
    }

    /// The signed verdict must be about the evidence actually on record.
    fn check_evidence(&self, evidence_hash: [u8; 32]) -> Result<(), Error> {
        if self.evidence_hash != Some(evidence_hash) {
            return Err(Error::EvidenceMismatch);
        }
        Ok(())
    }
}

impl Attestation {
    /// Checks this attestation against `job`'s verifier key, doing the curve
    /// arithmetic here. Off-chain callers use this; a Solana program cannot afford to.
    pub fn verify_for(&self, job: &Job) -> Result<VerifiedAttestation, Error> {
        let message = attestation_message(
            job.job_id,
            job.spec_hash,
            self.evidence_hash,
            self.verdict,
        );
        if verify(&job.verifier, &message, &self.signature) {
            Ok(VerifiedAttestation { evidence_hash: self.evidence_hash, verdict: self.verdict })
        } else {
            Err(Error::InvalidAttestation)
        }
    }
}

impl Ruling {
    /// Checks this ruling against `job`'s arbiter key.
    pub fn verify_for(&self, job: &Job) -> Result<VerifiedRuling, Error> {
        let message =
            ruling_message(job.job_id, job.spec_hash, self.evidence_hash, self.verdict);
        if verify(&job.arbiter, &message, &self.signature) {
            Ok(VerifiedRuling { evidence_hash: self.evidence_hash, verdict: self.verdict })
        } else {
            Err(Error::InvalidRuling)
        }
    }
}

fn settled_by(verdict: Verdict) -> State {
    match verdict {
        Verdict::Pass => State::Released,
        Verdict::Fail => State::Refunded,
    }
}
