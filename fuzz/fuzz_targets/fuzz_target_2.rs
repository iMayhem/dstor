#![no_main]

use libfuzzer_sys::fuzz_target;
use dstore::crypto::{encrypt_chunk, decrypt_chunk, EncryptedChunk};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Use first 32 bytes as key (or pad if shorter)
    let mut key_bytes = [0u8; 32];
    let copy_len = data.len().min(32);
    key_bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    let key = Zeroizing::new(key_bytes);

    // Use rest of data as plaintext
    let plaintext = &data[32.min(data.len())..];
    if plaintext.is_empty() {
        return;
    }

    // Encrypt
    let enc = encrypt_chunk(&key, plaintext);

    // Decrypt with correct key
    let decrypted = decrypt_chunk(&key, &enc);
    assert!(decrypted.is_some(), "Decryption with correct key must succeed");
    let decrypted = decrypted.unwrap();
    assert_eq!(decrypted.len(), plaintext.len(), "Decrypted length must match");
    assert_eq!(&decrypted[..], plaintext, "Decrypted data must match original");

    // Decrypt with wrong key should fail
    let mut wrong_key_bytes = key_bytes;
    wrong_key_bytes[0] ^= 0xFF;
    let wrong_key = Zeroizing::new(wrong_key_bytes);
    let wrong_decrypted = decrypt_chunk(&wrong_key, &enc);
    // Should either return None or garbage (but typically None with AEAD)
    if let Some(bad) = wrong_decrypted {
        // If it somehow returns data, it must not match (AEAD should prevent this)
        assert_ne!(&bad[..], plaintext, "Wrong key must not produce correct plaintext");
    }

    // Manipulated ciphertext must fail decryption
    let mut tampered = EncryptedChunk {
        nonce: enc.nonce,
        ciphertext: enc.ciphertext.clone(),
    };
    if !tampered.ciphertext.is_empty() {
        tampered.ciphertext[0] ^= 0x01;
        let tampered_decrypted = decrypt_chunk(&key, &tampered);
        assert!(tampered_decrypted.is_none(), "Tampered ciphertext must fail decryption");
    }

    // Wrong nonce must fail
    let mut wrong_nonce = enc.nonce;
    wrong_nonce[0] ^= 0x01;
    let wrong_nonce_enc = EncryptedChunk {
        nonce: wrong_nonce,
        ciphertext: enc.ciphertext.clone(),
    };
    let wrong_nonce_decrypted = decrypt_chunk(&key, &wrong_nonce_enc);
    assert!(wrong_nonce_decrypted.is_none(), "Wrong nonce must fail decryption");
});
