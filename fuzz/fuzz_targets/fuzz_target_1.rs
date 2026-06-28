#![no_main]

use libfuzzer_sys::fuzz_target;
use dstore::erasure;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let num_data = (data[0] as usize % 8).max(1);
    let num_parity = (data[1] as usize % 4).max(1);
    let chunk_size = (data[2] as usize % 4096).max(16);

    // Build data shards
    let mut shards: Vec<Vec<u8>> = Vec::new();
    let mut offset = 3;
    for _ in 0..num_data {
        let end = (offset + chunk_size).min(data.len());
        shards.push(data[offset..end].to_vec());
        offset = end;
        if offset >= data.len() {
            break;
        }
    }
    if shards.len() < 2 {
        return;
    }
    let original_sizes: Vec<usize> = shards.iter().map(|s| s.len()).collect();
    let actual_data = shards.len();
    let actual_parity = num_parity.min(4);

    // Encode
    let encoded = match erasure::encode_stripe(&shards, actual_parity) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Try decoding with all shards present
    let all_available: Vec<Option<Vec<u8>>> = encoded.iter().map(|s| Some(s.clone())).collect();
    let decoded = erasure::decode_stripe(&all_available, actual_data, actual_parity, &original_sizes);
    assert!(decoded.is_ok(), "Full decode must succeed");
    let decoded = decoded.unwrap();
    for (i, d) in decoded.iter().enumerate() {
        assert_eq!(&d[..], &shards[i][..], "Decoded shard {} must match original", i);
    }

    // Try decoding with some missing shards (if enough remain)
    if actual_data >= 3 {
        let mut partial: Vec<Option<Vec<u8>>> = (0..encoded.len()).map(|_| None).collect();
        // Use a subset that still has enough shards
        let keep = actual_data; // keep only data shards, drop parity
        for i in 0..keep.min(encoded.len()) {
            partial[i] = Some(encoded[i].clone());
        }
        let partial_sizes: Vec<usize> = original_sizes.iter().map(|&s| s).collect();
        let partial_decoded = erasure::decode_stripe(&partial, actual_data, actual_parity, &partial_sizes);
        assert!(partial_decoded.is_ok(), "Partial decode ({} of {} shards) must succeed", keep, encoded.len());
    }
});
