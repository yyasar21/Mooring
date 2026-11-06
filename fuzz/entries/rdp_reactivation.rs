//! Fuzz entry `rdp_reactivation`: framed server PDUs (`[len16, bytes]`) through the
//! Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3) the way `active::reactivate`
//! drives it after a `DeactivateAll` (review 5 L-28, A4 F1).

/// Never panics; a finalized desktop outside `MAX_DIM` is refused before it allocates.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::fuzz::reactivation(data);
}
