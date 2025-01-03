use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS;
use tfhe::shortint::{Ciphertext, ClientKey, ServerKey, gen_keys};

use std::fmt::Write;
use std::time::Instant;

pub fn gen_nibble_keys() -> (ClientKey, ServerKey) {
    let start = Instant::now();
    let (ck, sk) = gen_keys(PARAM_MESSAGE_4_CARRY_4_KS_PBS);
    println!("gen keys time           {:.2?}", start.elapsed());

    (ck, sk)
}

pub fn gen_crumb_keys() -> (ClientKey, ServerKey) {
    let start = Instant::now();
    let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    println!("gen keys time           {:.2?}", start.elapsed());

    (ck, sk)
}

pub fn enc_nibble_vec(input: &[u8], ck: &ClientKey) -> Vec<Ciphertext> {
    let enc_ck: Vec<_> = input
        .iter()
        .flat_map(|&byte| {
            let lsb = byte & 0x0F;
            let msb = (byte >> 4) & 0x0F;
            vec![ck.encrypt(msb.into()), ck.encrypt(lsb.into())]
        })
        .collect();

    enc_ck
}

pub fn dec_nibble_vec(enc: &[Ciphertext], ck: &ClientKey) -> Vec<u8> {
    assert!(enc.len() % 2 == 0, "Encrypted vector length must be even.");

    let mut output = Vec::with_capacity(enc.len() / 2);
    for chunk in enc.chunks(2) {
        let msb = ck.decrypt(&chunk[0]) as u8;
        let lsb = ck.decrypt(&chunk[1]) as u8;

        let byte = (msb << 4) | lsb;
        output.push(byte);
    }

    output
}

pub fn enc_crumb_vec(input: &[u8], ck: &ClientKey) -> Vec<Ciphertext> {
    let enc_ck: Vec<_> = input
        .iter()
        .flat_map(|&byte| {
            let lsb1 = byte & 0x03;
            let lsb2 = (byte >> 2) & 0x03;
            let msb1 = (byte >> 4) & 0x03;
            let msb2 = (byte >> 6) & 0x03;
            vec![
                ck.encrypt(msb2.into()),
                ck.encrypt(msb1.into()),
                ck.encrypt(lsb2.into()),
                ck.encrypt(lsb1.into()),
            ]
        })
        .collect();

    enc_ck
}

pub fn print_hex_nibble_fhe(label: &str, idx: usize, enc_data: &[Ciphertext], ck: &ClientKey) {
    let mut state: Vec<u8> = Vec::new();

    for enc_value in enc_data.iter() {
        state.push(ck.decrypt(enc_value) as u8);
    }

    let mut hex_output = String::new();
    for byte in state.iter() {
        write!(&mut hex_output, "{:01x}", byte).unwrap();
    }
    println!("{}  {:?} {}", label, idx, hex_output);
}
