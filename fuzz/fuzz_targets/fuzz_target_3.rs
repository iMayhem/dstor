#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize arbitrary bytes as Manifest
    if let Ok(manifest) = serde_json::from_slice::<dstore::chunk::Manifest>(data) {
        // Roundtrip: serialize back
        if let Ok(serialized) = serde_json::to_vec(&manifest) {
            // Deserialize again
            if let Ok(manifest2) = serde_json::from_slice::<dstore::chunk::Manifest>(&serialized) {
                // Verify key fields survive roundtrip
                assert_eq!(manifest.file_name, manifest2.file_name);
                assert_eq!(manifest.file_size, manifest2.file_size);
                assert_eq!(manifest.total_chunks, manifest2.total_chunks);
                assert_eq!(manifest.chunks.len(), manifest2.chunks.len());
                if manifest.data_shards != 0 || manifest.parity_shards != 0 {
                    assert_eq!(manifest.data_shards, manifest2.data_shards);
                    assert_eq!(manifest.parity_shards, manifest2.parity_shards);
                }
            }
        }
    }

    // Try to deserialize arbitrary bytes as ChunkInfo
    if let Ok(info) = serde_json::from_slice::<dstore::chunk::ChunkInfo>(data) {
        if let Ok(serialized) = serde_json::to_vec(&info) {
            if let Ok(info2) = serde_json::from_slice::<dstore::chunk::ChunkInfo>(&serialized) {
                assert_eq!(info.hash, info2.hash);
                assert_eq!(info.index, info2.index);
                assert_eq!(info.size, info2.size);
                assert_eq!(info.nonce, info2.nonce);
                assert_eq!(info.is_parity, info2.is_parity);
                assert_eq!(info.stripe_index, info2.stripe_index);
            }
        }
    }
});
