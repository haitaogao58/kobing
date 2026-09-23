use rsbinder::BinderFeatures;

pub const KEYMASTER_BLOB_HW_PREFIX: &[u8] = b"pKMblob\x00";

pub const KEYMASTER_BLOB_SW_PREFIX: &[u8] = b"pKMblob\x01";

pub const RPC_SOCKET_CONTEXT: &str = "u:r:keystore:s0";

pub fn sid_features() -> BinderFeatures {
    let mut features = BinderFeatures::default();
    features.set_requesting_sid = true;

    features
}
