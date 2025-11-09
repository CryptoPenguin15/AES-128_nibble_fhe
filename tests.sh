cargo test --release -- --nocapture ::test_endianess -- --exact
cargo test --release -- --nocapture ::test_key_expansion -- --exact
cargo test --release -- --nocapture ::test_init_arr_ciphertext ::test_init_vec_ciphertext -- --exact
cargo test --release -- --nocapture ::test_bivariate_lookup_sbox_tfhe -- --exact
cargo test --release -- --nocapture ::test_bivariate_lookup_gmul2_tfhe ::test_bivariate_lookup_gmul3_tfhe -- --exact
cargo test --release -- --nocapture ::test_perf_nibble_xor ::test_perf_crumb_xor -- --exact
cargo test --release -- --nocapture ::test_encrypt_block_tfhe1 -- --exact
cargo test --release -- --nocapture ::test_encrypt_block_tfhe2 -- --exact
cargo test --release -- --nocapture ::test_encrypt_decrypt_rnd_block -- --exact

cargo run --release -- -n 1 -i "0123456789abcdef" -k "0123456789abcdef0123456789abcdef"
cargo run --release -- -n 2 -i "0123456789abcdef" -k "0123456789abcdef0123456789abcdef"

echo "READY!"
