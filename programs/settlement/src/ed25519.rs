//! Verification of an `Ed25519SigVerify` precompile call via the `instructions` sysvar.
//!
//! Solana's ed25519 program runs outside the BPF VM entirely (native code, essentially
//! free in compute units). The standard way a program relies on it: the client puts an
//! `Ed25519SigVerify` instruction in the same transaction, and the program checks -- via
//! the `instructions` sysvar, which exposes every instruction in the currently executing
//! transaction -- that such an instruction exists and verified exactly the (pubkey,
//! message, signature) triple the program cares about. This module never runs ed25519
//! math; it only compares bytes the runtime already validated against what the caller
//! claims to be releasing or resolving on. That comparison is the entire trust boundary,
//! which is why it gets its own module and its own focused tests.
//!
//! Convention used here: the precompile instruction must be the one immediately before
//! the current instruction in the transaction (`get_instruction_relative(-1, ..)`). This
//! is the same fixed-adjacency convention `solana-ed25519-program`'s own doc examples and
//! most production Anchor programs use; it avoids the ambiguity of scanning the whole
//! transaction for "any" ed25519 instruction (which would let an attacker pad a tx with
//! decoy ed25519 instructions and reason about which one a naive scanner picks).

use anchor_lang::prelude::*;
use solana_instructions_sysvar::get_instruction_relative;
use solana_sdk_ids::ed25519_program;

use crate::errors::SettlementError;

const SIGNATURE_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;
/// num_signatures (u8) + padding (u8).
const HEADER_LEN: usize = 2;
/// `Ed25519SignatureOffsets`: 7 little-endian `u16` fields.
const OFFSETS_LEN: usize = 14;
/// Sentinel `solana-ed25519-program`'s instruction builder (and every client that follows
/// the same convention) uses in the `*_instruction_index` fields to mean "this same
/// instruction" rather than pointing at a different instruction in the transaction.
const CURRENT_INSTRUCTION: u16 = u16::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignatureOffsets {
    signature_offset: u16,
    signature_instruction_index: u16,
    public_key_offset: u16,
    public_key_instruction_index: u16,
    message_data_offset: u16,
    message_data_size: u16,
    message_instruction_index: u16,
}

fn read_u16(data: &[u8], at: usize) -> core::result::Result<u16, SettlementError> {
    let bytes = data.get(at..at + 2).ok_or(SettlementError::MalformedEd25519Instruction)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn parse_offsets(data: &[u8]) -> core::result::Result<SignatureOffsets, SettlementError> {
    if data.len() < HEADER_LEN + OFFSETS_LEN {
        return Err(SettlementError::MalformedEd25519Instruction);
    }
    let num_signatures = data[0];
    if num_signatures != 1 {
        // Every attestation/ruling check here is over exactly one signature. A precompile
        // instruction verifying zero, or a batch of several, doesn't match the shape this
        // program ever asks a client to build.
        return Err(SettlementError::MalformedEd25519Instruction);
    }

    let base = HEADER_LEN;
    Ok(SignatureOffsets {
        signature_offset: read_u16(data, base)?,
        signature_instruction_index: read_u16(data, base + 2)?,
        public_key_offset: read_u16(data, base + 4)?,
        public_key_instruction_index: read_u16(data, base + 6)?,
        message_data_offset: read_u16(data, base + 8)?,
        message_data_size: read_u16(data, base + 10)?,
        message_instruction_index: read_u16(data, base + 12)?,
    })
}

fn slice_at(data: &[u8], offset: u16, len: usize) -> core::result::Result<&[u8], SettlementError> {
    let start = offset as usize;
    let end = start.checked_add(len).ok_or(SettlementError::MalformedEd25519Instruction)?;
    data.get(start..end).ok_or(SettlementError::MalformedEd25519Instruction)
}

/// Check that `data` -- the instruction data of a call to the ed25519 program -- proves
/// `expected_pubkey` signed exactly `expected_message` producing exactly
/// `expected_signature`.
///
/// Pure and runtime-independent by design: no `AccountInfo`, no sysvar, just bytes in and
/// a verdict out. That's what lets the attack-case tests below drive it directly with
/// hand-built buffers instead of needing a simulated validator.
fn verify_ed25519_ix_data(
    data: &[u8],
    expected_pubkey: &[u8; 32],
    expected_message: &[u8],
    expected_signature: &[u8; 64],
) -> core::result::Result<(), SettlementError> {
    let offsets = parse_offsets(data)?;

    // Every offset must be self-referential (point back into *this* instruction's data).
    // If any of them named a different instruction index, the bytes we're about to read
    // and compare below wouldn't be the bytes the runtime actually ran ed25519 over -- an
    // attacker could get a real signature verified over unrelated data elsewhere in the
    // transaction and then aim these offsets at whatever bytes they like.
    if offsets.signature_instruction_index != CURRENT_INSTRUCTION
        || offsets.public_key_instruction_index != CURRENT_INSTRUCTION
        || offsets.message_instruction_index != CURRENT_INSTRUCTION
    {
        return Err(SettlementError::MalformedEd25519Instruction);
    }

    // Reject any size mismatch before slicing: a shorter declared message than expected
    // would otherwise let a prefix match and hide a length-manipulation attack.
    if offsets.message_data_size as usize != expected_message.len() {
        return Err(SettlementError::Ed25519WrongMessage);
    }

    let pubkey = slice_at(data, offsets.public_key_offset, PUBKEY_LEN)?;
    let signature = slice_at(data, offsets.signature_offset, SIGNATURE_LEN)?;
    let message = slice_at(data, offsets.message_data_offset, expected_message.len())?;

    if pubkey != expected_pubkey.as_slice() {
        return Err(SettlementError::Ed25519WrongSigner);
    }
    if message != expected_message {
        return Err(SettlementError::Ed25519WrongMessage);
    }
    if signature != expected_signature.as_slice() {
        return Err(SettlementError::Ed25519WrongSignature);
    }
    Ok(())
}

/// Require that the instruction immediately before this one in the transaction is a
/// genuine `Ed25519SigVerify` precompile call that verified `expected_pubkey` over
/// `expected_message` with `expected_signature`.
pub fn require_previous_ed25519(
    instructions_sysvar: &AccountInfo,
    expected_pubkey: &[u8; 32],
    expected_message: &[u8],
    expected_signature: &[u8; 64],
) -> Result<()> {
    let ix = get_instruction_relative(-1, instructions_sysvar)
        .map_err(|_| error!(SettlementError::MissingEd25519Instruction))?;

    if ix.program_id != ed25519_program::ID {
        return Err(error!(SettlementError::MissingEd25519Instruction));
    }

    verify_ed25519_ix_data(&ix.data, expected_pubkey, expected_message, expected_signature)
        .map_err(|e| error!(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBKEY: [u8; 32] = [7u8; 32];
    const SIGNATURE: [u8; 64] = [9u8; 64];
    const MESSAGE: &[u8] = b"exactly the canonical bytes settlement-core signs, byte for byte";

    /// Builds the same byte layout `solana_ed25519_program::new_ed25519_instruction_with_signature`
    /// produces: header, offsets (all self-referential), pubkey, signature, message.
    fn well_formed_ix_data(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
        ix_data_with_indices(pubkey, signature, message, CURRENT_INSTRUCTION, CURRENT_INSTRUCTION, CURRENT_INSTRUCTION)
    }

    fn ix_data_with_indices(
        pubkey: &[u8; 32],
        signature: &[u8; 64],
        message: &[u8],
        sig_ix: u16,
        pk_ix: u16,
        msg_ix: u16,
    ) -> Vec<u8> {
        let pubkey_offset = (HEADER_LEN + OFFSETS_LEN) as u16;
        let signature_offset = pubkey_offset + PUBKEY_LEN as u16;
        let message_offset = signature_offset + SIGNATURE_LEN as u16;

        let mut data = Vec::new();
        data.push(1u8); // num_signatures
        data.push(0u8); // padding
        data.extend_from_slice(&signature_offset.to_le_bytes());
        data.extend_from_slice(&sig_ix.to_le_bytes());
        data.extend_from_slice(&pubkey_offset.to_le_bytes());
        data.extend_from_slice(&pk_ix.to_le_bytes());
        data.extend_from_slice(&message_offset.to_le_bytes());
        data.extend_from_slice(&(message.len() as u16).to_le_bytes());
        data.extend_from_slice(&msg_ix.to_le_bytes());
        data.extend_from_slice(pubkey);
        data.extend_from_slice(signature);
        data.extend_from_slice(message);
        data
    }

    #[test]
    fn accepts_a_well_formed_matching_instruction() {
        let data = well_formed_ix_data(&PUBKEY, &SIGNATURE, MESSAGE);
        assert_eq!(verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE), Ok(()));
    }

    // --- attack (c): the precompile verified a real signature, but by the wrong key ---
    #[test]
    fn rejects_wrong_signer_key() {
        let other_key = [1u8; 32];
        let data = well_formed_ix_data(&other_key, &SIGNATURE, MESSAGE);
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::Ed25519WrongSigner)
        );
    }

    // --- attack (b): the precompile verified a real signature, but over a different message ---
    #[test]
    fn rejects_wrong_message() {
        // Built to the same length as `MESSAGE` programmatically, not by hand-counting
        // characters in a string literal: same size, different content.
        let mut other_message = vec![b'x'; MESSAGE.len()];
        other_message[0] = b'!';
        let data = well_formed_ix_data(&PUBKEY, &SIGNATURE, &other_message);
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::Ed25519WrongMessage)
        );
    }

    #[test]
    fn rejects_message_of_a_different_length() {
        let data = well_formed_ix_data(&PUBKEY, &SIGNATURE, b"short");
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::Ed25519WrongMessage)
        );
    }

    #[test]
    fn rejects_mismatched_signature_bytes() {
        let other_sig = [3u8; 64];
        let data = well_formed_ix_data(&PUBKEY, &other_sig, MESSAGE);
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::Ed25519WrongSignature)
        );
    }

    #[test]
    fn rejects_a_batched_verification_of_more_than_one_signature() {
        let mut data = well_formed_ix_data(&PUBKEY, &SIGNATURE, MESSAGE);
        data[0] = 2; // claim two signatures
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::MalformedEd25519Instruction)
        );
    }

    #[test]
    fn rejects_truncated_instruction_data() {
        let data = vec![1u8, 0u8, 0u8]; // header + one stray byte, no offsets
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::MalformedEd25519Instruction)
        );
    }

    /// The offsets point at a *different* instruction's data instead of this one's -- even
    /// if the bytes at those fixed positions happened to look right, trusting a
    /// cross-instruction offset would mean checking bytes the runtime never actually ran
    /// ed25519 over for this call.
    #[test]
    fn rejects_offsets_pointing_at_another_instruction() {
        let data = ix_data_with_indices(&PUBKEY, &SIGNATURE, MESSAGE, 0, CURRENT_INSTRUCTION, CURRENT_INSTRUCTION);
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::MalformedEd25519Instruction)
        );
    }

    #[test]
    fn rejects_out_of_bounds_offsets() {
        let mut data = well_formed_ix_data(&PUBKEY, &SIGNATURE, MESSAGE);
        // Point the public key offset past the end of the buffer.
        let bad_offset: u16 = data.len() as u16 + 10;
        data[6..8].copy_from_slice(&bad_offset.to_le_bytes());
        assert_eq!(
            verify_ed25519_ix_data(&data, &PUBKEY, MESSAGE, &SIGNATURE),
            Err(SettlementError::MalformedEd25519Instruction)
        );
    }
}
