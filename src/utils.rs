use blake2_rfc::blake2b::blake2b;
use rand_core::SeedableRng;
use rand_pcg::Lcg64Xsh32;

pub fn make_prng(id: u16) -> Lcg64Xsh32 {
    let seed = blake2b(16, b"kampela", &id.to_be_bytes())
        .as_bytes()
        .try_into()
        .expect("static length");
    SeedableRng::from_seed(seed)
}

pub fn msg_len_as_usize(msg_len: [u8; 3]) -> usize {
    let mut msg_len_be_bytes = [0; 4];
    msg_len_be_bytes[1..4].copy_from_slice(&msg_len);
    u32::from_be_bytes(msg_len_be_bytes) as usize
}
