// override aes file from maestro since si and sii are private
use maestro::rep3_core::{party::{error::MpcResult, MainParty, Party}, share::RssShare};
use maestro::{share::gf8::GF8, util::ArithmeticBlackBox};
pub mod ss;

pub trait GF8InvBlackBox {
    /// returns a (2,3) sharing of the public constant `value`
    fn constant(&self, value: GF8) -> RssShare<GF8>;
    /// computes inversion of the (2,3) sharing of s (si,sii) in-place
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()>;

    /// run any required pre-processing phase to prepare for computation of the key schedule with n_keys and n_blocks many AES-128/AES-256 block calls
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize, variant: AesVariant) -> MpcResult<()>;

    fn main_party_mut(&mut self) -> &mut MainParty;
}

// contains n AES States in parallel (ie si has length n * 16)
#[derive(Clone)]
pub struct VectorAesState {
    pub si: Vec<GF8>,            // MADE PUBLIC
    pub sii: Vec<GF8>,           // MADE PUBLIC
    pub n: usize,
}

impl VectorAesState {
    pub fn new(n: usize) -> Self {
        Self {
            si: vec![GF8(0u8); n * 16],
            sii: vec![GF8(0u8); n * 16],
            n,
        }
    }

    // fills AES states column-wise (as in FIPS 97)
    // bytes.len() must be a multiple of 16
    pub fn from_bytes(bytes: Vec<RssShare<GF8>>) -> Self {
        let n: usize = bytes.len() / 16;
        debug_assert_eq!(16 * n, bytes.len());
        let mut state: VectorAesState = Self::new(n);
        for k in 0..n {
            for i in 0..4 {
                for j in 0..4 {
                    state.si[16 * k + 4 * i + j] = bytes[16 * k + 4 * j + i].si;
                    state.sii[16 * k + 4 * i + j] = bytes[16 * k + 4 * j + i].sii;
                }
            }
        }
        state
    }

    // outputs the AES states column-wise (as in FIPS 97)
    pub fn to_bytes(&self) -> Vec<RssShare<GF8>> {
        let mut vec = Vec::with_capacity(self.n * 16);
        for k in 0..self.n {
            for i in 0..4 {
                for j in 0..4 {
                    vec.push(RssShare::from(
                        self.si[16 * k + 4 * j + i],
                        self.sii[16 * k + 4 * j + i],
                    ));
                }
            }
        }
        vec
    }

    fn with_capacity(n: usize) -> Self {
        Self {
            si: Vec::with_capacity(16 * n),
            sii: Vec::with_capacity(16 * n),
            n,
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.si.append(&mut other.si);
        self.sii.append(&mut other.sii);
        self.n += other.n;
    }

    #[inline]
    fn permute4(&mut self, start: usize, perm: [usize; 4]) {
        let tmp_i = [
            self.si[start],
            self.si[start + 1],
            self.si[start + 2],
            self.si[start + 3],
        ];
        let tmp_ii = [
            self.sii[start],
            self.sii[start + 1],
            self.sii[start + 2],
            self.sii[start + 3],
        ];
        for i in 0..4 {
            self.si[start + i] = tmp_i[perm[i]];
            self.sii[start + i] = tmp_ii[perm[i]];
        }
    }

    pub fn shift_rows(&mut self) {
        for i in 0..self.n {
            // rotate row 2 by 1 to the left
            self.permute4(16 * i + 4, [1, 2, 3, 0]);
            // rotate row 3 by 2 to the left
            self.permute4(16 * i + 8, [2, 3, 0, 1]);
            // rotate row 4 by 3 to the left
            self.permute4(16 * i + 12, [3, 0, 1, 2]);
        }
    }

    pub fn inv_shift_rows(&mut self) {
        for i in 0..self.n {
            // rotate row 2 by 1 to the right
            self.permute4(16 * i + 4, [3, 0, 1, 2]);
            // rotate row 3 by 2 to the right
            self.permute4(16 * i + 8, [2, 3, 0, 1]);
            // rotate row 4 by 3 to the right
            self.permute4(16 * i + 12, [1, 2, 3, 0]);
        }
    }

    #[inline]
    fn mix_single_column(&mut self, start: usize) {
        let c0 = RssShare::from(self.si[start], self.sii[start]);
        let c1 = RssShare::from(self.si[start + 4], self.sii[start + 4]);
        let c2 = RssShare::from(self.si[start + 8], self.sii[start + 8]);
        let c3 = RssShare::from(self.si[start + 12], self.sii[start + 12]);

        let m0 = c0 * GF8(0x2) + c1 * GF8(0x3) + c2 + c3;
        let m1 = c0 + c1 * GF8(0x2) + c2 * GF8(0x3) + c3;
        let m2 = c0 + c1 + c2 * GF8(0x2) + c3 * GF8(0x3);
        let m3 = c0 * GF8(0x3) + c1 + c2 + c3 * GF8(0x2);
        self.si[start] = m0.si;
        self.sii[start] = m0.sii;
        self.si[start + 4] = m1.si;
        self.sii[start + 4] = m1.sii;
        self.si[start + 8] = m2.si;
        self.sii[start + 8] = m2.sii;
        self.si[start + 12] = m3.si;
        self.sii[start + 12] = m3.sii;
    }

    pub fn mix_columns(&mut self) {
        for i in 0..self.n {
            self.mix_single_column(16 * i);
            self.mix_single_column(16 * i + 1);
            self.mix_single_column(16 * i + 2);
            self.mix_single_column(16 * i + 3);
        }
    }

    #[inline]
    fn inv_mix_single_column(&mut self, start: usize) {
        let c0 = RssShare::from(self.si[start], self.sii[start]);
        let c1 = RssShare::from(self.si[start + 4], self.sii[start + 4]);
        let c2 = RssShare::from(self.si[start + 8], self.sii[start + 8]);
        let c3 = RssShare::from(self.si[start + 12], self.sii[start + 12]);

        let m0 = c0 * GF8(0xe) + c1 * GF8(0xb) + c2 * GF8(0xd) + c3 * GF8(0x9);
        let m1 = c0 * GF8(0x9) + c1 * GF8(0xe) + c2 * GF8(0xb) + c3 * GF8(0xd);
        let m2 = c0 * GF8(0xd) + c1 * GF8(0x9) + c2 * GF8(0xe) + c3 * GF8(0xb);
        let m3 = c0 * GF8(0xb) + c1 * GF8(0xd) + c2 * GF8(0x9) + c3 * GF8(0xe);
        self.si[start] = m0.si;
        self.sii[start] = m0.sii;
        self.si[start + 4] = m1.si;
        self.sii[start + 4] = m1.sii;
        self.si[start + 8] = m2.si;
        self.sii[start + 8] = m2.sii;
        self.si[start + 12] = m3.si;
        self.sii[start + 12] = m3.sii;
    }

    pub fn inv_mix_columns(&mut self) {
        for i in 0..self.n {
            self.inv_mix_single_column(16 * i);
            self.inv_mix_single_column(16 * i + 1);
            self.inv_mix_single_column(16 * i + 2);
            self.inv_mix_single_column(16 * i + 3);
        }
    }
}

/// A row-wise representation of the AES (round) key
#[derive(Clone)]
pub struct AesKeyState {
    pub si: [GF8; 16],           // MADE PUBLIC
    pub sii: [GF8; 16],        // MADE PUBLIC         
}

impl Default for AesKeyState {
    fn default() -> Self {
        Self::new()
    }
}

impl AesKeyState {
    /// Returns a all zero state
    pub fn new() -> Self {
        Self {
            si: [GF8(0); 16],
            sii: [GF8(0); 16],
        }
    }

    // vec is interpreted as column-wise (see FIPS 97)
    pub fn from_bytes(vec: Vec<RssShare<GF8>>) -> Self {
        debug_assert_eq!(vec.len(), 16);
        let mut state = Self::new();
        for i in 0..4 {
            for j in 0..4 {
                state.si[4 * i + j] = vec[4 * j + i].si;
                state.sii[4 * i + j] = vec[4 * j + i].sii;
            }
        }
        state
    }

    // vec must be in row-wise representation
    pub fn from_rss_vec(vec: Vec<RssShare<GF8>>) -> Self {
        debug_assert_eq!(16, vec.len());
        let mut state = Self::new();
        for (i, x) in vec.into_iter().enumerate() {
            state.si[i] = x.si;
            state.sii[i] = x.sii;
        }
        state
    }

    pub fn to_rss_vec(&self) -> Vec<RssShare<GF8>> {
        let mut out = Vec::with_capacity(16);
        for i in 0..16 {
            out.push(RssShare::from(self.si[i], self.sii[i]));
        }
        out
    }
}

pub fn random_state<Protocol: Party>(
    party: &mut Protocol,
    size: usize,
) -> VectorAesState {
    VectorAesState::from_bytes(party.generate_random(size * 16))
}

/// returns random key states for benchmarking purposes
pub fn random_keyschedule<Protocol: Party>(
    party: &mut Protocol,
    variant: AesVariant,
) -> Vec<AesKeyState> {
    (0..variant.n_rounds()+1)
        .map(|_| {
            let rk = party.generate_random(16);
            AesKeyState::from_rss_vec(rk)
        })
        .collect()
}

pub fn zero_keyschedule<Protocol: Party>(
    party: &mut Protocol,
    variant: AesVariant,
) -> Vec<AesKeyState> {
    println!("Zero key schedule");
    // aes128_keyschedule(party, vec![RssShare::from(GF8(0), GF8(0)); 16]).unwrap()
    (0..variant.n_rounds()+1)
        .map(|_| AesKeyState::new())
        .collect()
}

macro_rules! timer {
    ($a:literal, {$b:expr;}) => {
        // #[cfg(feature = "verbose-timing")]
        // let time_start = Instant::now();
        $b;
        // #[cfg(feature = "verbose-timing")]
        // PARTY_TIMER
        //     .lock()
        //     .unwrap()
        //     .report_time($a, time_start.elapsed());
    };
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AesVariant {
    Aes128,
    Aes256
}

impl AesVariant {
    const fn key_len(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    pub const fn n_rounds(&self) -> usize {
        match self {
            Self::Aes128 => 10,
            Self::Aes256 => 14,
        }
    }

    /// Returns the number of S-boxes in the key schedule.
    pub const fn n_ks_sboxes(&self) -> usize {
        match self {
            Self::Aes128 => 40,
            Self::Aes256 => 52,
        }
    }
}

pub fn aes128_no_keyschedule<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    inputs: VectorAesState,
    round_key: &[AesKeyState],
) -> MpcResult<VectorAesState> {
    aes_no_keyschedule(AesVariant::Aes128, party, inputs, round_key)
}

pub fn aes256_no_keyschedule<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    inputs: VectorAesState,
    round_key: &[AesKeyState],
) -> MpcResult<VectorAesState> {
    aes_no_keyschedule(AesVariant::Aes256, party, inputs, round_key)
}

fn aes_no_keyschedule<Protocol: GF8InvBlackBox>(
    variant: AesVariant,
    party: &mut Protocol,
    inputs: VectorAesState,
    round_key: &[AesKeyState],
) -> MpcResult<VectorAesState> {
    debug_assert_eq!(round_key.len(), variant.n_rounds()+1);
    let mut state = inputs;

    timer!("aes_add_rk", {
        add_round_key(&mut state, &round_key[0]);
    });

    #[allow(clippy::needless_range_loop)]
    for r in 1..variant.n_rounds() {
        timer!("aes_sbox", {
            sbox_layer(party, &mut state.si, &mut state.sii)?;
        });
        timer!("aes_shift_rows", {
            state.shift_rows();
        });
        timer!("aes_mix_columns", {
            state.mix_columns();
        });
        timer!("aes_add_rk", {
            add_round_key(&mut state, &round_key[r]);
        });
    }
    timer!("aes_sbox", {
        sbox_layer(party, &mut state.si, &mut state.sii)?;
    });
    timer!("aes_shift_rows", {
        state.shift_rows();
    });

    timer!("aes_add_rk", {
        add_round_key(&mut state, &round_key[variant.n_rounds()]);
    });

    Ok(state)
}

pub fn aes128_inv_no_keyschedule<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    inputs: VectorAesState,
    key_schedule: &[AesKeyState],
) -> MpcResult<VectorAesState> {
    debug_assert_eq!(key_schedule.len(), 11);
    let mut state = inputs;

    add_round_key(&mut state, &key_schedule[10]);
    for r in (1..=9).rev() {
        state.inv_shift_rows();
        inv_sbox_layer(party, &mut state.si, &mut state.sii)?;
        add_round_key(&mut state, &key_schedule[r]);
        state.inv_mix_columns();
    }
    state.inv_shift_rows();
    inv_sbox_layer(party, &mut state.si, &mut state.sii)?;
    add_round_key(&mut state, &key_schedule[0]);
    Ok(state)
}

fn aes128_keyschedule_round<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    rk: &AesKeyState,
    rcon: GF8,
) -> MpcResult<AesKeyState> {
    let mut rot_i = [rk.si[7], rk.si[11], rk.si[15], rk.si[3]];
    let mut rot_ii = [rk.sii[7], rk.sii[11], rk.sii[15], rk.sii[3]];
    sbox_layer(party, &mut rot_i, &mut rot_ii)?;

    let mut output = rk.clone();
    for i in 0..4 {
        output.si[4 * i] += rot_i[i];
        output.sii[4 * i] += rot_ii[i];
    }
    let rcon = party.constant(rcon);
    output.si[0] += rcon.si;
    output.sii[0] += rcon.sii;

    for j in 1..4 {
        for i in 0..4 {
            output.si[4 * i + j] += output.si[4 * i + j - 1];
            output.sii[4 * i + j] += output.sii[4 * i + j - 1];
        }
    }
    Ok(output)
}

pub fn aes128_keyschedule<Protocol: GF8InvBlackBox>(
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
        let rki = aes128_keyschedule_round(party, &ks[i - 1], ROUND_CONSTANTS[i - 1])?;
        ks.push(rki);
    }
    Ok(ks)
}

pub fn aes256_keyschedule<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    mut key: Vec<RssShare<GF8>>,
) -> MpcResult<Vec<AesKeyState>> {
    debug_assert_eq!(key.len(), 32);
    const ROUND_CONSTANTS: [GF8; 7] = [GF8(0x01), GF8(0x02), GF8(0x04), GF8(0x08), GF8(0x10), GF8(0x20), GF8(0x40)];
    let mut ks = Vec::with_capacity(15);
    let key2 = key.split_off(16);
    ks.push(AesKeyState::from_bytes(key)); // rk0
    ks.push(AesKeyState::from_bytes(key2)); // rk1
    
    for i in 1..=7 {
        // RotWord
        let mut rot_i = [ks[2*i-1].si[7], ks[2*i-1].si[11], ks[2*i-1].si[15], ks[2*i-1].si[3]];
        let mut rot_ii = [ks[2*i-1].sii[7], ks[2*i-1].sii[11], ks[2*i-1].sii[15], ks[2*i-1].sii[3]];
        // SubWord
        sbox_layer(party, &mut rot_i, &mut rot_ii)?;
        // Add Rcon
        let rcon = party.constant(ROUND_CONSTANTS[i - 1]);
        rot_i[0] += rcon.si;
        rot_ii[0] += rcon.sii;

        let mut rki = ks[2*i-2].clone();
        // Add temp
        for i in 0..4 {
            rki.si[4 * i] += rot_i[i];
            rki.sii[4 * i] += rot_ii[i];
        }
        // Add remaining
        for j in 1..4 {
            for i in 0..4 {
                rki.si[4 * i + j] += rki.si[4 * i + j - 1];
                rki.sii[4 * i + j] += rki.sii[4 * i + j - 1];
            }
        }
        
        ks.push(rki);
        if i < 7 {
            let mut rki = ks[2*i-1].clone();
            // no RotWord
            let mut sub_i = [ks[2*i].si[3], ks[2*i].si[7], ks[2*i].si[11], ks[2*i].si[15]];
            let mut sub_ii = [ks[2*i].sii[3], ks[2*i].sii[7], ks[2*i].sii[11], ks[2*i].sii[15]];
            // SubWord
            sbox_layer(party, &mut sub_i, &mut sub_ii)?;
            // Add temp
            for i in 0..4 {
                rki.si[4 * i] += sub_i[i];
                rki.sii[4 * i] += sub_ii[i];
            }
            // Add remaining
            for j in 1..4 {
                for i in 0..4 {
                    rki.si[4 * i + j] += rki.si[4 * i + j - 1];
                    rki.sii[4 * i + j] += rki.sii[4 * i + j - 1];
                }
            }
            ks.push(rki);
        }
    }
    Ok(ks)
}

pub fn output<Protocol: ArithmeticBlackBox<GF8>>(
    party: &mut Protocol,
    blocks: VectorAesState,
) -> MpcResult<Vec<GF8>> {
    let shares = blocks.to_bytes();
    let (si, sii): (Vec<_>, Vec<_>) = shares.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    party.output_round(&si, &sii)
}

pub(super) fn add_round_key(states: &mut VectorAesState, round_key: &AesKeyState) {
    for j in 0..states.n {
        for i in 0..16 {
            states.si[16 * j + i] += round_key.si[i];
            states.sii[16 * j + i] += round_key.sii[i];
        }
    }
}

fn sbox_layer<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    // first inverse, then affine transform
    party.gf8_inv(si, sii)?;

    // apply affine transform
    let c = party.constant(GF8(0x63));
    for i in 0..si.len() {
        si[i] = si[i].aes_sbox_affine_transform() + c.si;
        sii[i] = sii[i].aes_sbox_affine_transform() + c.sii;
    }
    Ok(())
}

fn inv_sbox_layer<Protocol: GF8InvBlackBox>(
    party: &mut Protocol,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    // first inverse affine transform, then gf8 inverse
    // apply inverse affine transform
    let c = party.constant(GF8(0x63));
    for i in 0..si.len() {
        si[i] = (si[i] + c.si).inv_aes_sbox_affine_transform();
        sii[i] = (sii[i] + c.sii).inv_aes_sbox_affine_transform();
    }
    party.gf8_inv(si, sii)
}

pub const INV_GF8: [u8; 256] = [
    0x0, 0x1, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7,
    0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2,
    0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0xa, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,
    0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19,
    0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x9,
    0xed, 0x5c, 0x5, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,
    0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b,
    0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x6, 0xa1, 0xfa, 0x81, 0x82,
    0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x2, 0xb9, 0xa4,
    0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a,
    0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62,
    0xc, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,
    0xb, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0xf, 0xa9, 0x27, 0x53, 0x4, 0x1b, 0xfc, 0xac, 0xe6,
    0x7a, 0x7, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b,
    0xb1, 0xd, 0xd6, 0xeb, 0xc6, 0xe, 0xcf, 0xad, 0x8, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,
    0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x3, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c,
];