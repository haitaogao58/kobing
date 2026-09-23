// Copyright 2023, The Android Open Source Project
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

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyFormat::KeyFormat, KeyOrigin::KeyOrigin, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    Tag::Tag, TagType::TagType,
};
use crate::err as ks_err;
use crate::keymaster::crypto::hmac_sha256;
use crate::keymaster::error::Error;
use anyhow::Result;
use std::mem::size_of;

#[cfg(test)]
mod tests;

const SOFTWARE_ROOT_OF_TRUST: &[u8] = b"SW";

macro_rules! bloberr {
    { $($arg:tt)+ } => {
        anyhow::Error::new(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(ks_err!($($arg)+))
    };
}

fn get_tag_value(params: &[KeyParameter], tag: Tag) -> Option<&KeyParameterValue> {
    params
        .iter()
        .find_map(|kp| if kp.tag == tag { Some(&kp.value) } else { None })
}

fn tag_type(tag: &Tag) -> TagType {
    TagType((tag.0 as u32 & 0xf0000000) as i32)
}

pub fn export_key(
    data: &[u8],
    params: &[KeyParameter],
) -> Result<(KeyFormat, Vec<u8>, Vec<KeyParameter>)> {
    let hidden = hidden_params(params, &[SOFTWARE_ROOT_OF_TRUST]);
    let KeyBlob {
        key_material,
        hw_enforced,
        sw_enforced,
    } = KeyBlob::new_from_serialized(data, &hidden)?;

    let mut combined = hw_enforced;
    combined.extend_from_slice(&sw_enforced);

    let algo_val =
        get_tag_value(&combined, Tag::ALGORITHM).ok_or_else(|| bloberr!("No algorithm found!"))?;

    let format = match algo_val {
        KeyParameterValue::Algorithm(Algorithm::AES)
        | KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES)
        | KeyParameterValue::Algorithm(Algorithm::HMAC) => KeyFormat::RAW,
        KeyParameterValue::Algorithm(Algorithm::RSA)
        | KeyParameterValue::Algorithm(Algorithm::EC) => KeyFormat::PKCS8,
        _ => return Err(bloberr!("Unexpected algorithm {:?}", algo_val)),
    };

    let key_material = match (format, algo_val) {
        (KeyFormat::PKCS8, KeyParameterValue::Algorithm(Algorithm::EC)) => {
            let curve = get_tag_value(&combined, Tag::EC_CURVE)
                .ok_or_else(|| bloberr!("Failed to determine curve for EC key!"))?;
            match curve {
                KeyParameterValue::EcCurve(EcCurve::CURVE_25519) => key_material,
                KeyParameterValue::EcCurve(EcCurve::P_224) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_224)?
                }
                KeyParameterValue::EcCurve(EcCurve::P_256) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_256)?
                }
                KeyParameterValue::EcCurve(EcCurve::P_384) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_384)?
                }
                KeyParameterValue::EcCurve(EcCurve::P_521) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_521)?
                }
                _ => {
                    return Err(bloberr!("Unexpected EC curve {curve:?}"));
                }
            }
        }
        (KeyFormat::RAW, _) => key_material,
        (format, algo) => {
            return Err(bloberr!(
                "Unsupported combination of {format:?} format for {algo:?} algorithm"
            ));
        }
    };
    Ok((format, key_material, combined))
}

const DER_ALGORITHM_ID_P224: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x21,
];

const DER_ALGORITHM_ID_P256: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];

const DER_ALGORITHM_ID_P384: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x22,
];

const DER_ALGORITHM_ID_P521: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x23,
];

const DER_VERSION_0: &[u8] = &[0x02, 0x01, 0x00];

fn pkcs8_wrap_nist_key(nist_key: &[u8], curve: EcCurve) -> Result<Vec<u8>> {
    let der_alg_id = match curve {
        EcCurve::P_224 => DER_ALGORITHM_ID_P224,
        EcCurve::P_256 => DER_ALGORITHM_ID_P256,
        EcCurve::P_384 => DER_ALGORITHM_ID_P384,
        EcCurve::P_521 => DER_ALGORITHM_ID_P521,
        _ => return Err(bloberr!("unknown curve {curve:?}")),
    };

    let mut nist_key_octet_string = Vec::new();
    nist_key_octet_string.push(0x04);
    add_der_len(&mut nist_key_octet_string, nist_key.len())?;
    nist_key_octet_string.extend_from_slice(nist_key);

    let mut buf = Vec::new();
    buf.push(0x30);
    add_der_len(
        &mut buf,
        DER_VERSION_0.len() + der_alg_id.len() + nist_key_octet_string.len(),
    )?;
    buf.extend_from_slice(DER_VERSION_0);
    buf.extend_from_slice(der_alg_id);
    buf.extend_from_slice(&nist_key_octet_string);
    Ok(buf)
}

fn add_der_len(buf: &mut Vec<u8>, len: usize) -> Result<()> {
    if len <= 0x7f {
        buf.push(len as u8)
    } else if len <= 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    } else {
        return Err(bloberr!("Unsupported DER length {len}"));
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
struct KeyBlob {
    key_material: Vec<u8>,

    hw_enforced: Vec<KeyParameter>,

    sw_enforced: Vec<KeyParameter>,
}

impl KeyBlob {
    const KEY_BLOB_VERSION: u8 = 0;

    const LEGACY_HMAC_KEY: &'static [u8] = b"IntegrityAssuredBlob0\0";

    const MAC_LEN: usize = 8;

    fn new_from_serialized(mut data: &[u8], hidden: &[KeyParameter]) -> Result<Self> {
        if data.len() < (1 + 3 * size_of::<u32>() + Self::MAC_LEN) {
            return Err(bloberr!("blob not long enough (len = {})", data.len()));
        }

        let mac = &data[data.len() - Self::MAC_LEN..];
        let computed_mac = Self::compute_hmac(&data[..data.len() - Self::MAC_LEN], hidden)?;
        if mac != computed_mac {
            return Err(bloberr!("invalid key blob"));
        }

        let version = consume_u8(&mut data)?;
        if version != Self::KEY_BLOB_VERSION {
            return Err(bloberr!("unexpected blob version {}", version));
        }
        let key_material = consume_vec(&mut data)?;
        let hw_enforced = deserialize_params(&mut data)?;
        let sw_enforced = deserialize_params(&mut data)?;

        let rest = &data[Self::MAC_LEN..];
        if !rest.is_empty() {
            return Err(bloberr!("extra data (len {})", rest.len()));
        }
        Ok(KeyBlob {
            key_material,
            hw_enforced,
            sw_enforced,
        })
    }

    fn compute_hmac(data: &[u8], hidden: &[KeyParameter]) -> Result<Vec<u8>> {
        let hidden_data = serialize_params(hidden)?;
        let mut combined = data.to_vec();
        combined.extend_from_slice(&hidden_data);
        let mut tag = hmac_sha256(Self::LEGACY_HMAC_KEY, &combined)?;
        tag.truncate(Self::MAC_LEN);
        Ok(tag)
    }
}

fn hidden_params(params: &[KeyParameter], rots: &[&[u8]]) -> Vec<KeyParameter> {
    let mut results = Vec::new();
    if let Some(app_id) = get_tag_value(params, Tag::APPLICATION_ID) {
        results.push(KeyParameter {
            tag: Tag::APPLICATION_ID,
            value: app_id.clone(),
        });
    }
    if let Some(app_data) = get_tag_value(params, Tag::APPLICATION_DATA) {
        results.push(KeyParameter {
            tag: Tag::APPLICATION_DATA,
            value: app_data.clone(),
        });
    }
    for rot in rots {
        results.push(KeyParameter {
            tag: Tag::ROOT_OF_TRUST,
            value: KeyParameterValue::Blob(rot.to_vec()),
        });
    }
    results
}

fn consume_u8(data: &mut &[u8]) -> Result<u8> {
    match data.first() {
        Some(b) => {
            *data = &(*data)[1..];
            Ok(*b)
        }
        None => Err(bloberr!("failed to find 1 byte")),
    }
}

fn consume_bool(data: &mut &[u8]) -> Result<bool> {
    let b = consume_u8(data)?;
    if b == 0x01 {
        Ok(true)
    } else {
        Err(bloberr!("bool value other than 1 encountered"))
    }
}

fn consume_u32(data: &mut &[u8]) -> Result<u32> {
    const LEN: usize = size_of::<u32>();
    if data.len() < LEN {
        return Err(bloberr!("failed to find {LEN} bytes"));
    }
    let chunk: [u8; LEN] = data[..LEN].try_into().unwrap();
    *data = &(*data)[LEN..];
    Ok(u32::from_ne_bytes(chunk))
}

fn consume_i32(data: &mut &[u8]) -> Result<i32> {
    const LEN: usize = size_of::<i32>();
    if data.len() < LEN {
        return Err(bloberr!("failed to find {LEN} bytes"));
    }
    let chunk: [u8; LEN] = data[..LEN].try_into().unwrap();
    *data = &(*data)[4..];
    Ok(i32::from_ne_bytes(chunk))
}

fn consume_i64(data: &mut &[u8]) -> Result<i64> {
    const LEN: usize = size_of::<i64>();
    if data.len() < LEN {
        return Err(bloberr!("failed to find {LEN} bytes"));
    }
    let chunk: [u8; LEN] = data[..LEN].try_into().unwrap();
    *data = &(*data)[LEN..];
    Ok(i64::from_ne_bytes(chunk))
}

fn consume_vec(data: &mut &[u8]) -> Result<Vec<u8>> {
    let len = consume_u32(data)? as usize;
    if len > data.len() {
        return Err(bloberr!("failed to find {} bytes", len));
    }
    let result = data[..len].to_vec();
    *data = &(*data)[len..];
    Ok(result)
}

fn consume_blob(
    data: &mut &[u8],
    next_blob_offset: &mut usize,
    blob_data: &[u8],
) -> Result<Vec<u8>> {
    let data_len = consume_u32(data)? as usize;
    let data_offset = consume_u32(data)? as usize;

    if data_offset != *next_blob_offset {
        return Err(bloberr!(
            "got blob offset {} instead of {}",
            data_offset,
            next_blob_offset
        ));
    }
    if (data_offset + data_len) > blob_data.len() {
        return Err(bloberr!(
            "blob at offset [{}..{}+{}] goes beyond blob data size {}",
            data_offset,
            data_offset,
            data_len,
            blob_data.len(),
        ));
    }

    let slice = &blob_data[data_offset..data_offset + data_len];
    *next_blob_offset += data_len;
    Ok(slice.to_vec())
}

fn deserialize_params(data: &mut &[u8]) -> Result<Vec<KeyParameter>> {
    let blob_data_size = consume_u32(data)? as usize;
    if blob_data_size > data.len() {
        return Err(bloberr!(
            "blob data size {} bigger than data (len={})",
            blob_data_size,
            data.len()
        ));
    }

    let blob_data = &data[..blob_data_size];
    let mut next_blob_offset = 0;

    *data = &data[blob_data_size..];

    let param_count = consume_u32(data)? as usize;
    let param_size = consume_u32(data)? as usize;
    if param_size > data.len() {
        return Err(bloberr!(
            "size mismatch 4+{}+4+4+{} > {}",
            blob_data_size,
            param_size,
            data.len()
        ));
    }

    let mut results = Vec::new();
    for _i in 0..param_count {
        let tag_num = consume_u32(data)? as i32;
        let tag = Tag(tag_num);
        let value = match tag_type(&tag) {
            TagType::INVALID => return Err(bloberr!("invalid tag {:?} encountered", tag)),
            TagType::ENUM | TagType::ENUM_REP => {
                let val = consume_i32(data)?;
                match tag {
                    Tag::ALGORITHM => KeyParameterValue::Algorithm(Algorithm(val)),
                    Tag::BLOCK_MODE => KeyParameterValue::BlockMode(BlockMode(val)),
                    Tag::PADDING => KeyParameterValue::PaddingMode(PaddingMode(val)),
                    Tag::DIGEST | Tag::RSA_OAEP_MGF_DIGEST => {
                        KeyParameterValue::Digest(Digest(val))
                    }
                    Tag::EC_CURVE => KeyParameterValue::EcCurve(EcCurve(val)),
                    Tag::ORIGIN => KeyParameterValue::Origin(KeyOrigin(val)),
                    Tag::PURPOSE => KeyParameterValue::KeyPurpose(KeyPurpose(val)),
                    Tag::USER_AUTH_TYPE => {
                        KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType(val))
                    }
                    _ => KeyParameterValue::Integer(val),
                }
            }
            TagType::UINT | TagType::UINT_REP => KeyParameterValue::Integer(consume_i32(data)?),
            TagType::ULONG | TagType::ULONG_REP => {
                KeyParameterValue::LongInteger(consume_i64(data)?)
            }
            TagType::DATE => KeyParameterValue::DateTime(consume_i64(data)?),
            TagType::BOOL => KeyParameterValue::BoolValue(consume_bool(data)?),
            TagType::BIGNUM | TagType::BYTES => {
                KeyParameterValue::Blob(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            _ => return Err(bloberr!("unexpected tag type for {:?}", tag)),
        };
        results.push(KeyParameter { tag, value });
    }

    Ok(results)
}

fn serialize_params(params: &[KeyParameter]) -> Result<Vec<u8>> {
    let mut result = vec![0; 4];

    let mut blob_size = 0u32;
    for param in params {
        let tag_type = tag_type(&param.tag);
        if let KeyParameterValue::Blob(v) = &param.value {
            if tag_type != TagType::BIGNUM && tag_type != TagType::BYTES {
                return Err(bloberr!(
                    "unexpected tag type for tag {:?} with blob",
                    param.tag
                ));
            }
            result.extend_from_slice(v);
            blob_size += v.len() as u32;
        }
    }

    result[..4].clone_from_slice(&blob_size.to_ne_bytes());

    result.extend_from_slice(&(params.len() as u32).to_ne_bytes());

    let params_size_offset = result.len();
    result.extend_from_slice(&[0u8; 4]);
    let first_param_offset = result.len();
    let mut blob_offset = 0u32;
    for param in params {
        result.extend_from_slice(&(param.tag.0 as u32).to_ne_bytes());
        match &param.value {
            KeyParameterValue::Invalid(_v) => {
                return Err(bloberr!("invalid tag found in {:?}", param))
            }

            KeyParameterValue::Algorithm(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::BlockMode(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::PaddingMode(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::Digest(v) => result.extend_from_slice(&(v.0 as u32).to_ne_bytes()),
            KeyParameterValue::EcCurve(v) => result.extend_from_slice(&(v.0 as u32).to_ne_bytes()),
            KeyParameterValue::Origin(v) => result.extend_from_slice(&(v.0 as u32).to_ne_bytes()),
            KeyParameterValue::KeyPurpose(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::HardwareAuthenticatorType(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }

            KeyParameterValue::Integer(v) => result.extend_from_slice(&(*v as u32).to_ne_bytes()),
            KeyParameterValue::BoolValue(_v) => result.push(0x01u8),
            KeyParameterValue::LongInteger(v) | KeyParameterValue::DateTime(v) => {
                result.extend_from_slice(&(*v as u64).to_ne_bytes())
            }
            KeyParameterValue::Blob(v) => {
                let blob_len = v.len() as u32;
                result.extend_from_slice(&blob_len.to_ne_bytes());
                result.extend_from_slice(&blob_offset.to_ne_bytes());
                blob_offset += blob_len;
            }

            _ => return Err(bloberr!("unknown value found in {:?}", param)),
        }
    }
    let serialized_size = (result.len() - first_param_offset) as u32;

    result[params_size_offset..params_size_offset + 4]
        .clone_from_slice(&serialized_size.to_ne_bytes());
    Ok(result)
}
