use crate::data::Input;
use maestro::{aes::VectorAesState, rep3_core::{network::{ConnectedParty,task::Direction::{Next, Previous}}, share::RssShare}, share::gf8::GF8};
use maestro::{aes::{ss::{GF8InvBlackBoxSS, GF8InvBlackBoxSSMal}, GF8InvBlackBox}, lut256::{lut256_ss::{Lut256SSMalParty, Lut256SSParty}, LUT256Party}};

pub fn rss_input(library_input: &Input, party: &mut Lut256SSMalParty) -> Option<VectorAesState> {
    let input_bytes: Vec<GF8> = library_input.iter().map(|&b| GF8(b)).collect::<Vec<_>>();
    
    let input: VectorAesState = if party.main_party_mut().i == 0 {
        // Party 0 provides the secret input and creates shares
        println!("– Input: {}", String::from_utf8_lossy(&input_bytes.iter().map(|x| x.0).collect::<Vec<_>>()));
        println!("Number of 16-byte blocks: {}", library_input.num_blocks());
        // println!("Party bytes input: {:?}", input_bytes.iter().map(|x| x.0).collect::<Vec<_>>());

        // println!("Input bytes as hex: 0x{}", input_bytes.iter()
        //     .map(|&x| format!("{:02x}", x.0))
        //     .collect::<Vec<_>>()
        //     .join(""));     

        // Convert bytes to shares and distribute them
        let shared_bytes: Vec<RssShare<GF8>> = input_bytes.iter()
            .map(|&b| {
                // Generate random shares that sum to b
                let si: GF8 = GF8(rand::random::<u8>());
                let sii: GF8 = b - si;
                // Send sii to party 1 and si to party 2
                party.main_party_mut().io().send_field_slice(Next, vec![sii].as_slice());
                party.main_party_mut().io().send_field_slice(Previous, vec![si].as_slice());
                RssShare { si, sii }
            })
            .collect();
        
        VectorAesState::from_bytes(shared_bytes)
    } else {
        // Other parties receive their shares
        let num_bytes = library_input.iter().len();
        let mut shares = vec![GF8(0); 16*library_input.num_blocks()];
        if party.main_party_mut().i == 1 {
            party.main_party_mut().io().receive_field_slice(Previous, &mut shares).rcv().unwrap();
        } else {
            
            party.main_party_mut().io().receive_field_slice(Next, &mut shares).rcv().unwrap();
        }
        
        let shared_bytes: Vec<RssShare<GF8>> = shares.into_iter()
            .map(|share| {
                if party.main_party_mut().i == 1 {
                    RssShare { si: share, sii: GF8(0) }
                } else { // party 2
                    RssShare { si: GF8(0), sii: share }
                }
            })
            .collect();

        VectorAesState::from_bytes(shared_bytes)
    };

    Some(input)
}