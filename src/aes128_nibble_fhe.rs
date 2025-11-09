use crate::aes_fhe::{dec_nibble_vec, enc_nibble_vec, gen_nibble_keys, print_hex_nibble_fhe};
use crate::aes128_keyschedule::{BLOCKSIZE, KEYSIZE, ROUNDKEYSIZE, ROUNDS};
use crate::aes128_tables::{GMUL2, GMUL3, SBOX, gen_tbl};

use tfhe::shortint::server_key::BivariateLookupTableOwned;
use tfhe::shortint::{Ciphertext, ClientKey, ServerKey};

use std::time::Instant;

use rayon::prelude::*;

#[inline]
fn add_round_key_fhe(state: &mut [Ciphertext], rkey: &[Ciphertext], sk: &ServerKey) {
    let start = Instant::now();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = sk.unchecked_bitxor(elem, &rkey[i]);
    });

    println!("add_round_key_fhe       {:.2?}", start.elapsed());
}

#[inline]
pub fn sub_bytes_fhe(
    state: &mut [Ciphertext],
    sbox_msb: &BivariateLookupTableOwned,
    sbox_lsb: &BivariateLookupTableOwned,
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(state.len() % 2 == 0);
    let tmp = state.to_vec();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        if i % 2 == 0 {
            *elem = sk.apply_lookup_table_bivariate(&tmp[i], &tmp[i + 1], sbox_msb);
        } else {
            *elem = sk.apply_lookup_table_bivariate(&tmp[i - 1], &tmp[i], sbox_lsb);
        }
    });

    println!("sub_bytes_fhe           {:.2?}", start.elapsed());
}

#[inline]
fn shift_rows_fhe(state: &mut [Ciphertext]) {
    let start = Instant::now();
    let tmp = state.to_vec();

    // col. 0
    state[0] = tmp[0].clone();
    state[1] = tmp[1].clone();
    state[2] = tmp[2 * 5].clone();
    state[2 + 1] = tmp[2 * 5 + 1].clone();
    state[2 * 2] = tmp[2 * 10].clone();
    state[2 * 2 + 1] = tmp[2 * 10 + 1].clone();
    state[2 * 3] = tmp[2 * 15].clone();
    state[2 * 3 + 1] = tmp[2 * 15 + 1].clone();

    // col. 1
    state[2 * 4] = tmp[2 * 4].clone();
    state[2 * 4 + 1] = tmp[2 * 4 + 1].clone();
    state[2 * 5] = tmp[2 * 9].clone();
    state[2 * 5 + 1] = tmp[2 * 9 + 1].clone();
    state[2 * 6] = tmp[2 * 14].clone();
    state[2 * 6 + 1] = tmp[2 * 14 + 1].clone();
    state[2 * 7] = tmp[2 * 3].clone();
    state[2 * 7 + 1] = tmp[2 * 3 + 1].clone();

    // col. 2
    state[2 * 8] = tmp[2 * 8].clone();
    state[2 * 8 + 1] = tmp[2 * 8 + 1].clone();
    state[2 * 9] = tmp[2 * 13].clone();
    state[2 * 9 + 1] = tmp[2 * 13 + 1].clone();
    state[2 * 10] = tmp[2 * 2].clone();
    state[2 * 10 + 1] = tmp[2 * 2 + 1].clone();
    state[2 * 11] = tmp[2 * 7].clone();
    state[2 * 11 + 1] = tmp[2 * 7 + 1].clone();

    // col. 3
    state[2 * 12] = tmp[2 * 12].clone();
    state[2 * 12 + 1] = tmp[2 * 12 + 1].clone();
    state[2 * 13] = tmp[2].clone();
    state[2 * 13 + 1] = tmp[2 + 1].clone();
    state[2 * 14] = tmp[2 * 6].clone();
    state[2 * 14 + 1] = tmp[2 * 6 + 1].clone();
    state[2 * 15] = tmp[2 * 11].clone();
    state[2 * 15 + 1] = tmp[2 * 11 + 1].clone();

    println!("shift_rows_fhe          {:.2?}", start.elapsed());
}

#[inline]
fn lut_state(
    state: &mut [Ciphertext],
    msb: &BivariateLookupTableOwned,
    lsb: &BivariateLookupTableOwned,
    sk: &ServerKey,
) -> [Ciphertext; 32] {
    let start = Instant::now();
    assert!(state.len() == 32);

    let mut tmp = state.to_vec();
    tmp.par_iter_mut().enumerate().for_each(|(i, elem)| {
        if i % 2 == 0 {
            *elem = sk.apply_lookup_table_bivariate(&state[i], &state[i + 1], msb);
        } else {
            *elem = sk.apply_lookup_table_bivariate(&state[i - 1], &state[i], lsb);
        }
    });

    println!("m_col lut time          {:.2?}", start.elapsed());
    let tmp: [Ciphertext; 32] = tmp.try_into().expect("Expected a Vec of length 32");

    tmp
}

#[inline]
fn parallel_xor(
    g1_g2_xor: &mut [Ciphertext],
    g1_state: &[Ciphertext],
    g2_state: &[Ciphertext],
    idx1: &[usize],
    idx2: &[usize],
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(idx1.len() == 4);
    assert!(idx2.len() == 4);

    g1_g2_xor
        .par_iter_mut()
        .with_max_len(1)
        .enumerate()
        .for_each(|(i, elem)| {
            let mut c: usize = i / 8; // 0..=7 => 0, 8..=15 => 1, 16..=23 => 2, 24..=31 => 3
            c *= 8;

            if i % 2 == 0 {
                let p: usize = ((i + 1) / 2) % 4; // (0, 0), (2, 1), (4, 2), (6, 3), (8, 0)
                *elem = sk.unchecked_bitxor(&g1_state[c + idx1[p]], &g2_state[c + idx2[p]]);
            } else {
                let p: usize = (i / 2) % 4;
                *elem = sk.unchecked_bitxor(&g1_state[c + idx1[p] + 1], &g2_state[c + idx2[p] + 1]);
            }
        });

    println!("m_col gx xor gy time    {:.2?}", start.elapsed());
}

#[inline]
fn mix_columns_fhe(
    state: &mut [Ciphertext],
    gmul2_msb: &BivariateLookupTableOwned,
    gmul2_lsb: &BivariateLookupTableOwned,
    gmul3_msb: &BivariateLookupTableOwned,
    gmul3_lsb: &BivariateLookupTableOwned,
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(state.len() == 32);

    let g2_state = lut_state(state, gmul2_msb, gmul2_lsb, sk);
    let g3_state = lut_state(state, gmul3_msb, gmul3_lsb, sk);

    let mut binding: Vec<Ciphertext> = (0..32).map(|_| sk.create_trivial(0)).collect();
    let g2_g3_xor = binding.as_mut_slice();
    let g2_idx = vec![0, 2, 4, 6];
    let g3_idx = vec![2, 4, 6, 0];
    parallel_xor(g2_g3_xor, &g2_state, &g3_state, &g2_idx, &g3_idx, sk);

    let mut binding: Vec<Ciphertext> = (0..32).map(|_| sk.create_trivial(0)).collect();
    let s1_s2_xor = binding.as_mut_slice();
    let s1_idx = vec![4, 0, 0, 2];
    let s2_idx = vec![6, 6, 2, 4];
    parallel_xor(s1_s2_xor, state, state, &s1_idx, &s2_idx, sk);

    state
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, state_elem)| {
            *state_elem = sk.unchecked_bitxor(&g2_g3_xor[i], &s1_s2_xor[i]);
        });

    println!("m_col time              {:.2?}", start.elapsed());
}

pub fn encrypt_one_block_fhe(
    input: &[u8; KEYSIZE],
    xk: &[u8; ROUNDKEYSIZE],
    output: &mut [u8; BLOCKSIZE],
    sk: &ServerKey,
    ck: &ClientKey,
) {
    let mut state = [0u8; BLOCKSIZE];
    state.copy_from_slice(input);

    let mut state_ck = enc_nibble_vec(&state, ck);
    let xk_ck = enc_nibble_vec(xk, ck);

    println!("generate_bivariate_tables");
    let (sbox_msb, sbox_lsb) = gen_tbl(&SBOX, sk);
    let (gmul2_msb, gmul2_lsb) = gen_tbl(&GMUL2, sk);
    let (gmul3_msb, gmul3_lsb) = gen_tbl(&GMUL3, sk);

    let start = Instant::now();

    print_hex_nibble_fhe("input", 0, &state_ck, ck);
    add_round_key_fhe(&mut state_ck, &xk_ck[..2 * BLOCKSIZE], sk);
    print_hex_nibble_fhe("k_sch", 0, &state_ck, ck);

    for round in 1..ROUNDS {
        sub_bytes_fhe(&mut state_ck, &sbox_msb, &sbox_lsb, sk);
        print_hex_nibble_fhe("s_box", round, &state_ck, ck);

        shift_rows_fhe(&mut state_ck);
        print_hex_nibble_fhe("s_row", round, &state_ck, ck);

        mix_columns_fhe(
            &mut state_ck,
            &gmul2_msb,
            &gmul2_lsb,
            &gmul3_msb,
            &gmul3_lsb,
            sk,
        );
        print_hex_nibble_fhe("m_col", round, &state_ck, ck);

        add_round_key_fhe(
            &mut state_ck,
            &xk_ck[round * 2 * KEYSIZE..2 * ROUNDKEYSIZE],
            sk,
        );
        print_hex_nibble_fhe("k_sch", round, &state_ck, ck);
    }

    sub_bytes_fhe(&mut state_ck, &sbox_msb, &sbox_lsb, sk);
    print_hex_nibble_fhe("s_box", 10, &state_ck, ck);

    shift_rows_fhe(&mut state_ck);
    print_hex_nibble_fhe("s_row", 10, &state_ck, ck);

    add_round_key_fhe(
        &mut state_ck,
        &xk_ck[2 * KEYSIZE * ROUNDS..2 * ROUNDKEYSIZE],
        sk,
    );
    print_hex_nibble_fhe("k_sch", 10, &state_ck, ck);

    println!("encrypt_block_fhe         {:.2?}", start.elapsed());

    let output_vec = dec_nibble_vec(&state_ck, ck);
    output.copy_from_slice(&output_vec);
}

pub fn encrypt_block_fhe(
    input: &[u8; KEYSIZE],
    xk: &[u8; ROUNDKEYSIZE],
    output: &mut [u8; BLOCKSIZE],
    iter: usize,
) {
    let mut state = [0u8; BLOCKSIZE];
    state.copy_from_slice(input);

    println!("generate_keys");
    let (ck, sk) = gen_nibble_keys();
    let mut state_ck = enc_nibble_vec(&state, &ck);
    let xk_ck = enc_nibble_vec(xk, &ck);

    println!("generate_bivariate_tables");
    let (sbox_msb, sbox_lsb) = gen_tbl(&SBOX, &sk);
    let (gmul2_msb, gmul2_lsb) = gen_tbl(&GMUL2, &sk);
    let (gmul3_msb, gmul3_lsb) = gen_tbl(&GMUL3, &sk);

    let tot = Instant::now();
    for i in 1..=iter {
        println!("Encrypting iteration: {}", i);

        let start = Instant::now();

        print_hex_nibble_fhe("input", 0, &state_ck, &ck);
        add_round_key_fhe(&mut state_ck, &xk_ck[..2 * BLOCKSIZE], &sk);
        print_hex_nibble_fhe("k_sch", 0, &state_ck, &ck);

        for round in 1..ROUNDS {
            sub_bytes_fhe(&mut state_ck, &sbox_msb, &sbox_lsb, &sk);
            print_hex_nibble_fhe("s_box", round, &state_ck, &ck);

            shift_rows_fhe(&mut state_ck);
            print_hex_nibble_fhe("s_row", round, &state_ck, &ck);

            mix_columns_fhe(
                &mut state_ck,
                &gmul2_msb,
                &gmul2_lsb,
                &gmul3_msb,
                &gmul3_lsb,
                &sk,
            );
            print_hex_nibble_fhe("m_col", round, &state_ck, &ck);

            add_round_key_fhe(
                &mut state_ck,
                &xk_ck[round * 2 * KEYSIZE..2 * ROUNDKEYSIZE],
                &sk,
            );
            print_hex_nibble_fhe("k_sch", round, &state_ck, &ck);
        }

        sub_bytes_fhe(&mut state_ck, &sbox_msb, &sbox_lsb, &sk);
        print_hex_nibble_fhe("s_box", 10, &state_ck, &ck);

        shift_rows_fhe(&mut state_ck);
        print_hex_nibble_fhe("s_row", 10, &state_ck, &ck);

        add_round_key_fhe(
            &mut state_ck,
            &xk_ck[2 * KEYSIZE * ROUNDS..2 * ROUNDKEYSIZE],
            &sk,
        );
        print_hex_nibble_fhe("k_sch", 10, &state_ck, &ck);

        println!("encrypt_block_fhe         {:.2?}", start.elapsed());
    }
    let elapsed = tot.elapsed();
    println!("AES of #{iter} outputs computed in: {elapsed:?}");

    let output_vec = dec_nibble_vec(&state_ck, &ck);
    output.copy_from_slice(&output_vec);
}
