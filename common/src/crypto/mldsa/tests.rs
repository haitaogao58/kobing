// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

const PKCS8_SEED_65_DATA: &str = concat!(
    "3034",
    "020100",
    "300b",
    "0609",
    "608648016503040312",
    "0422",
    "8020",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
);

const PKCS8_BOTH_65_DATA: &str = concat!(
    "303c",
    "020100",
    "300b",
    "0609",
    "608648016503040312",
    "042a",
    "3028",
    "0420",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "0404",
    "deadbeef"
);

const SEED: [u8; SEED_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[test]
fn parse_pkcs8_seed() {
    let key_data = hex::decode(PKCS8_SEED_65_DATA).unwrap();
    let key = import_pkcs8_key(&key_data).expect("PKCS8 parse failed");
    assert_eq!(
        key,
        KeyMaterial::MlDsa(
            MlDsaVariant::MlDsa65,
            OpaqueOr::Explicit(Key::MlDsa65(SEED))
        )
    );
}

#[test]
fn parse_pkcs8_both_fail() {
    let key_data = hex::decode(PKCS8_BOTH_65_DATA).unwrap();
    let result = import_pkcs8_key(&key_data);
    assert!(result.is_err());
}

#[test]
fn parse_pkcs8_failures() {
    let tests = [
        concat!(
            "801f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        ),
        concat!(
            "8020",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        ),
        concat!(
            "8021",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
        concat!(
            "8021",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        ),
        "8000",
        concat!(
            "3027",
            "041f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            "0401aa"
        ),
        concat!(
            "3029",
            "0421",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0401aa"
        ),
        concat!(
            "0420",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
    ];
    for hex_data in tests {
        let data = hex::decode(hex_data).unwrap();
        let result = import_pkcs8_key(&data);
        assert!(result.is_err(), "unexpected success parsing {hex_data}");
    }
}
