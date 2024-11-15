use maestro::{aes::{AesKeyState, GF8InvBlackBox}, rep3_core::{network::task::Direction::{Next, Previous}, share::RssShare, party::{error::MpcResult, MainParty, Party}}, share::gf8::GF8};
use maestro::{aes::{ss::{GF8InvBlackBoxSS, GF8InvBlackBoxSSMal}}, lut256::{lut256_ss::{Lut256SSMalParty, Lut256SSParty}, LUT256Party}};

const AES_KEYSHARE: [[u8; 16]; 3] = [
    // Party 0's share
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
    // Party 1's share
    [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
    // Party 2's share
    [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
];


fn aes128_keyschedule_round_mal<Protocol: GF8InvBlackBoxSSMal>(
    party: &mut Protocol,
    rk: &AesKeyState,
    rcon: GF8,
) -> MpcResult<AesKeyState> {
    // Get the last column and rotate
    let mut rot_i: [GF8; 4] = [rk.si[7], rk.si[11], rk.si[15], rk.si[3]];
    let mut rot_ii: [GF8; 4] = [rk.sii[7], rk.sii[11], rk.sii[15], rk.sii[3]];
    
    // Apply S-box to rotated word
    let mut state_ss: Vec<GF8> = vec![GF8(0); 4];
    party.gf8_inv_rss_to_ss(&mut state_ss, &rot_i, &rot_ii)?;
    
    // Apply affine transform
    let c = party.constant(GF8(0x63));
    state_ss.iter_mut().for_each(|dst| *dst = dst.aes_sbox_affine_transform() + c);
    
    // Convert back to RSS
    let mut new_rot_i: Vec<GF8> = vec![GF8(0); 4];
    let mut new_rot_ii: Vec<GF8> = vec![GF8(0); 4];
    party.gf8_inv_and_rss_output(&mut state_ss, &mut new_rot_i, &mut new_rot_ii)?;
    
    let mut output: AesKeyState = rk.clone();
    // XOR with first word of previous round key
    for i in 0..4 {
        output.si[4 * i] += new_rot_i[i];
        output.sii[4 * i] += new_rot_ii[i];
    }
    
    // Add round constant to first byte
    let rcon_rss: RssShare<GF8> = party.constant_rss(rcon);
    output.si[0] += rcon_rss.si;
    output.sii[0] += rcon_rss.sii;

    // Generate remaining words
    for j in 1..4 {
        for i in 0..4 {
            output.si[4 * i + j] += output.si[4 * i + j - 1];
            output.sii[4 * i + j] += output.sii[4 * i + j - 1];
        }
    }
    
    Ok(output)
}

pub fn aes128_keyschedule_mal<Protocol: GF8InvBlackBoxSSMal>(
    party: &mut Protocol,
    key: Vec<RssShare<GF8>>,
) -> MpcResult<Vec<AesKeyState>> {
    debug_assert_eq!(key.len(), 16);
    const ROUND_CONSTANTS: [GF8; 10] = [
        GF8(0x01),
        GF8(0x02),
        GF8(0x04),
        GF8(0x08),
        GF8(0x10),
        GF8(0x20),
        GF8(0x40),
        GF8(0x80),
        GF8(0x1b),
        GF8(0x36),
    ];
    
    let mut ks = Vec::with_capacity(11);
    ks.push(AesKeyState::from_bytes(key)); // rk0
    
    for i in 1..=10 {
        let rki = aes128_keyschedule_round_mal(party, &ks[i - 1], ROUND_CONSTANTS[i - 1])?;
        ks.push(rki);
    }
    
    Ok(ks)
}

pub fn keyshare_keyschedule(
    party: &mut Lut256SSMalParty,
) -> Vec<AesKeyState> {
    // Generate random shares for each byte of our key share
    let shared_key: Vec<RssShare<GF8>> = AES_KEYSHARE[party.main_party_mut().i].iter()
        .map(|&b| {
            // Generate random shares that sum to our part of the key
            let si = GF8(rand::random::<u8>());
            let sii = GF8(b) - si;
            
            // First round: all parties send their sii shares
            party.main_party_mut().io().send_field_slice(Next, vec![sii].as_slice());
            
            // First round: all parties receive from previous
            let mut received_si = vec![GF8(0); 1];
            party.main_party_mut().io().receive_field_slice(Previous, &mut received_si).rcv().unwrap();
            
            // Second round: all parties send their si shares
            party.main_party_mut().io().send_field_slice(Previous, vec![si].as_slice());
            
            // Second round: all parties receive from next
            let mut received_sii = vec![GF8(0); 1];
            party.main_party_mut().io().receive_field_slice(Next, &mut received_sii).rcv().unwrap();
            
            // Combine all shares
            RssShare {
                si: si + received_si[0],
                sii: sii + received_sii[0],
            }
        })
        .collect();

    // Create n_rounds + 1 copies of the key state
    // (0..variant.n_rounds()+1)
    //     .map(|_| AesKeyState::from_rss_vec(shared_key.clone()))
    //     .collect()
    aes128_keyschedule_mal(party, shared_key).unwrap()
}
