//! Fuzz entry `rdp_input`: bytes → pointer / key / wheel / unicode / release operations through the RDP input mapper.

/// Never panics.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::fuzz::input_sequence(data);
}
