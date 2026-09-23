// Copyright 2022, The Android Open Source Project
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

use crate::{
    crypto,
    crypto::{rsa::DecryptionMode, *},
    km_err, try_to_vec, vec_try_with_capacity, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{
        Algorithm, BlockMode, Digest, EcCurve, ErrorCode, KeyCharacteristics, KeyFormat, KeyParam,
        KeyPurpose, MlDsaVariant, PaddingMode, SecurityLevel, Tag, DEFAULT_CERT_SERIAL,
        DEFAULT_CERT_SUBJECT,
    },
    KeySizeInBits,
};
use log::{info, warn};
use std::vec::Vec;

mod info;
pub use info::*;
pub mod legacy;
#[cfg(test)]
mod tests;

pub const UNPOLICED_COPYABLE_TAGS: &[Tag] = &[
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::MaxUsesPerBoot,
    Tag::UserSecureId,
    Tag::NoAuthRequired,
    Tag::UserAuthType,
    Tag::AuthTimeout,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::UnlockedDeviceRequired,
    Tag::StorageKey,
];

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SecureStorage {
    Available,

    Unavailable,
}

#[macro_export]
macro_rules! get_tag_value {
    { $params:expr, $variant:ident, $err:expr } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(*v);
                }
            }
            match count {
                0 => Err($crate::km_verr!($err, "missing tag {}", stringify!($variant))),
                1 => Ok(result.unwrap()),
                _ => Err($crate::km_verr!($err, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

#[macro_export]
macro_rules! get_opt_tag_value {
    { $params:expr, $variant:ident } => {
        get_opt_tag_value!($params, $variant, InvalidTag)
    };
    { $params:expr, $variant:ident, $dup_error:ident } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(v);
                }
            }
            match count {
                0 => Ok(None),
                1 => Ok(Some(result.unwrap())),
                _ => Err($crate::km_err!($dup_error, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

#[macro_export]
macro_rules! get_bool_tag_value {
    { $params:expr, $variant:ident } => {
        {
            let mut count = 0;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant = param {
                    count += 1;
                }
            }
            match count {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

#[macro_export]
macro_rules! contains_tag_value {
    { $params:expr, $variant:ident, $value:expr } => {
        {
            let mut found = false;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    if *v == $value {
                        found = true;
                    }
                }
            }
            found
        }
    }
}

pub fn characteristics_valid(characteristics: &[KeyParam]) -> Result<(), Error> {
    let mut dup_checker = DuplicateTagChecker::default();
    for param in characteristics {
        let tag = param.tag();
        dup_checker.add(tag)?;
        if info(tag)?.characteristic == Characteristic::NotKeyCharacteristic {
            return Err(km_err!(
                InvalidKeyBlob,
                "tag {:?} is not a valid key characteristic",
                tag,
            ));
        }
    }
    Ok(())
}

pub fn transcribe_tags(
    dest: &mut Vec<KeyParam>,
    src: &[KeyParam],
    tags: &[Tag],
) -> Result<(), Error> {
    let mut dup_checker = DuplicateTagChecker::default();
    for param in src {
        let tag = param.tag();
        dup_checker.add(tag)?;
        if tags.contains(&tag) {
            dest.try_push(param.clone())?;
        }
    }
    Ok(())
}

pub fn get_algorithm(params: &[KeyParam]) -> Result<Algorithm, Error> {
    get_tag_value!(params, Algorithm, ErrorCode::UnsupportedAlgorithm)
}

pub fn get_block_mode(params: &[KeyParam]) -> Result<BlockMode, Error> {
    get_tag_value!(params, BlockMode, ErrorCode::UnsupportedBlockMode)
}

pub fn get_padding_mode(params: &[KeyParam]) -> Result<PaddingMode, Error> {
    get_tag_value!(params, Padding, ErrorCode::UnsupportedPaddingMode)
}

pub fn get_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)
}

pub fn get_ec_curve(params: &[KeyParam]) -> Result<EcCurve, Error> {
    get_tag_value!(params, EcCurve, ErrorCode::UnsupportedKeySize)
}

pub fn get_mldsa_variant(params: &[KeyParam]) -> Result<MlDsaVariant, Error> {
    get_tag_value!(params, MlDsaVariant, ErrorCode::UnsupportedMlDsaVariant)
}

pub fn get_mgf_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    Ok(*get_opt_tag_value!(params, RsaOaepMgfDigest)?.unwrap_or(&Digest::Sha1))
}

pub fn get_cert_serial(params: &[KeyParam]) -> Result<&[u8], Error> {
    Ok(get_opt_tag_value!(params, CertificateSerial)?
        .map(Vec::as_ref)
        .unwrap_or(DEFAULT_CERT_SERIAL))
}

pub fn characteristics_at(
    chars: &[KeyCharacteristics],
    sec_level: SecurityLevel,
) -> Result<&[KeyParam], Error> {
    let mut result: Option<&[KeyParam]> = None;
    for chars in chars {
        if chars.security_level != sec_level {
            continue;
        }
        if result.is_none() {
            result = Some(&chars.authorizations);
        } else {
            return Err(km_err!(
                InvalidKeyBlob,
                "multiple key characteristics at {:?}",
                sec_level
            ));
        }
    }
    result.ok_or_else(|| {
        km_err!(
            InvalidKeyBlob,
            "no parameters at security level {:?} found",
            sec_level
        )
    })
}

pub fn get_cert_subject(params: &[KeyParam]) -> Result<&[u8], Error> {
    Ok(get_opt_tag_value!(params, CertificateSubject)?
        .map(Vec::as_ref)
        .unwrap_or(DEFAULT_CERT_SUBJECT))
}

pub fn hidden(params: &[KeyParam], rot: &[u8]) -> Result<Vec<KeyParam>, Error> {
    let mut results = vec_try_with_capacity!(3)?;
    if let Ok(Some(app_id)) = get_opt_tag_value!(params, ApplicationId) {
        results.push(KeyParam::ApplicationId(try_to_vec(app_id)?));
    }
    if let Ok(Some(app_data)) = get_opt_tag_value!(params, ApplicationData) {
        results.push(KeyParam::ApplicationData(try_to_vec(app_data)?));
    }
    results.push(KeyParam::RootOfTrust(try_to_vec(rot)?));
    Ok(results)
}

pub fn extract_key_gen_characteristics(
    secure_storage: SecureStorage,
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<(Vec<KeyCharacteristics>, KeyGenInfo), Error> {
    let algorithm = get_algorithm(params)?;
    let keygen_info = match algorithm {
        Algorithm::Rsa => check_rsa_gen_params(params, sec_level),
        Algorithm::Ec => check_ec_gen_params(params, sec_level),
        Algorithm::MlDsa => check_mldsa_gen_params(params, sec_level),
        Algorithm::Aes => check_aes_gen_params(params, sec_level),
        Algorithm::TripleDes => check_3des_gen_params(params),
        Algorithm::Hmac => check_hmac_gen_params(params, sec_level),
    }?;
    Ok((
        extract_key_characteristics(secure_storage, algorithm, params, &[], sec_level)?,
        keygen_info,
    ))
}

pub fn extract_key_import_characteristics(
    imp: &crypto::Implementation,
    secure_storage: SecureStorage,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyCharacteristics>, KeyMaterial), Error> {
    let algorithm = get_algorithm(params)?;
    let (deduced_params, key_material) = match algorithm {
        Algorithm::Rsa => {
            check_rsa_import_params(&*imp.rsa, params, sec_level, key_format, key_data)
        }
        Algorithm::Ec => check_ec_import_params(&*imp.ec, params, sec_level, key_format, key_data),
        Algorithm::MlDsa => {
            check_mldsa_import_params(&*imp.mldsa, params, sec_level, key_format, key_data)
        }
        Algorithm::Aes => {
            check_aes_import_params(&*imp.aes, params, sec_level, key_format, key_data)
        }
        Algorithm::TripleDes => check_3des_import_params(&*imp.des, params, key_format, key_data),
        Algorithm::Hmac => {
            check_hmac_import_params(&*imp.hmac, params, sec_level, key_format, key_data)
        }
    }?;
    Ok((
        extract_key_characteristics(
            secure_storage,
            algorithm,
            params,
            &deduced_params,
            sec_level,
        )?,
        key_material,
    ))
}

fn extract_key_characteristics(
    secure_storage: SecureStorage,
    algorithm: Algorithm,
    params: &[KeyParam],
    extra_params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<Vec<KeyCharacteristics>, Error> {
    let mut chars = Vec::new();
    let mut keystore_chars = Vec::new();
    for param in params.iter().chain(extra_params) {
        let tag = param.tag();

        if AUTO_ADDED_CHARACTERISTICS.contains(&tag) {
            return Err(km_err!(
                InvalidTag,
                "KeyMint-added tag included on key generation/import"
            ));
        }

        if sec_level == SecurityLevel::Strongbox
            && [Tag::MaxUsesPerBoot, Tag::RollbackResistance].contains(&tag)
        {
            return Err(km_err!(
                InvalidTag,
                "tag {:?} not allowed in StrongBox",
                param.tag()
            ));
        }

        match param {
            KeyParam::KeySize(_) => {
                if algorithm == Algorithm::MlDsa {
                    continue;
                }
            }

            KeyParam::UsageCountLimit(use_limit) => match (use_limit, secure_storage) {
                (1, SecureStorage::Available) => {
                    chars.try_push(KeyParam::UsageCountLimit(*use_limit))?
                }
                (1, SecureStorage::Unavailable) | (_, _) => {
                    keystore_chars.try_push(KeyParam::UsageCountLimit(*use_limit))?
                }
            },
            _ => {}
        }

        if KEYMINT_ENFORCED_CHARACTERISTICS.contains(&tag) {
            chars.try_push(param.clone())?;
        } else if KEYSTORE_ENFORCED_CHARACTERISTICS.contains(&tag) {
            keystore_chars.try_push(param.clone())?;
        }
    }

    reject_incompatible_auth(&chars)?;

    chars.sort_by(legacy::param_compare);
    keystore_chars.sort_by(legacy::param_compare);

    let mut result = Vec::new();
    result.try_push(KeyCharacteristics {
        security_level: sec_level,
        authorizations: chars,
    })?;
    if !keystore_chars.is_empty() {
        result.try_push(KeyCharacteristics {
            security_level: SecurityLevel::Keystore,
            authorizations: keystore_chars,
        })?;
    }
    Ok(result)
}

fn check_rsa_key_size(key_size: KeySizeInBits, sec_level: SecurityLevel) -> Result<(), Error> {
    match key_size {
        KeySizeInBits(512) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(768) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(1024) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(2048) => Ok(()),
        KeySizeInBits(3072) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(4096) if sec_level != SecurityLevel::Strongbox => Ok(()),
        _ => Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE {:?} bits for RSA",
            key_size
        )),
    }
}

fn check_rsa_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    check_rsa_key_size(key_size, sec_level)?;
    let public_exponent = get_tag_value!(params, RsaPublicExponent, ErrorCode::InvalidArgument)?;

    check_rsa_params(params)?;
    Ok(KeyGenInfo::Rsa(key_size, public_exponent))
}

fn check_rsa_import_params(
    rsa: &dyn Rsa,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    if key_format != KeyFormat::Pkcs8 {
        return Err(km_err!(
            UnsupportedKeyFormat,
            "unsupported import format {:?}, expect PKCS8",
            key_format
        ));
    }
    let (key, key_size, public_exponent) = rsa.import_pkcs8_key(key_data, params)?;

    let mut deduced_chars = Vec::new();
    match get_opt_tag_value!(params, KeySize)? {
        Some(param_key_size) => {
            if *param_key_size != key_size {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified KEY_SIZE {:?} bits != actual key size {:?} for PKCS8 import",
                    param_key_size,
                    key_size
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::KeySize(key_size))?,
    }
    match get_opt_tag_value!(params, RsaPublicExponent)? {
        Some(param_public_exponent) => {
            if *param_public_exponent != public_exponent {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified RSA_PUBLIC_EXPONENT {:?} != actual exponent {:?} for PKCS8 import",
                    param_public_exponent,
                    public_exponent,
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::RsaPublicExponent(public_exponent))?,
    }
    check_rsa_key_size(key_size, sec_level)?;

    check_rsa_params(params)?;
    Ok((deduced_chars, key))
}

fn check_rsa_params(params: &[KeyParam]) -> Result<(), Error> {
    let mut seen_attest = false;
    let mut seen_non_attest = false;
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign | KeyPurpose::Decrypt | KeyPurpose::WrapKey => {
                    seen_non_attest = true
                }
                KeyPurpose::AttestKey => seen_attest = true,
                KeyPurpose::Verify | KeyPurpose::Encrypt => {}
                KeyPurpose::AgreeKey => {
                    warn!("Generating RSA key with invalid purpose {purpose:?}")
                }
            }
        }
    }
    if seen_attest && seen_non_attest {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }
    Ok(())
}

fn check_ec_gen_params(params: &[KeyParam], sec_level: SecurityLevel) -> Result<KeyGenInfo, Error> {
    let ec_curve = get_ec_curve(params)?;

    let purpose = check_ec_params(ec_curve, params, sec_level)?;
    let keygen_info = match (ec_curve, purpose) {
        (EcCurve::Curve25519, Some(KeyPurpose::Sign)) => KeyGenInfo::Ed25519,
        (EcCurve::Curve25519, Some(KeyPurpose::AttestKey)) => KeyGenInfo::Ed25519,
        (EcCurve::Curve25519, Some(KeyPurpose::AgreeKey)) => KeyGenInfo::X25519,
        (EcCurve::Curve25519, _) => {
            return Err(km_err!(
                IncompatiblePurpose,
                "curve25519 keys with invalid purpose {:?}",
                purpose
            ))
        }
        (EcCurve::P224, _) => KeyGenInfo::NistEc(ec::NistCurve::P224),
        (EcCurve::P256, _) => KeyGenInfo::NistEc(ec::NistCurve::P256),
        (EcCurve::P384, _) => KeyGenInfo::NistEc(ec::NistCurve::P384),
        (EcCurve::P521, _) => KeyGenInfo::NistEc(ec::NistCurve::P521),
    };
    Ok(keygen_info)
}

fn check_mldsa_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    let variant = get_mldsa_variant(params)?;

    check_mldsa_params(params, sec_level)?;
    Ok(KeyGenInfo::MlDsa(variant))
}

pub fn primary_purpose(params: &[KeyParam]) -> Result<KeyPurpose, Error> {
    params
        .iter()
        .find_map(|param| {
            if let KeyParam::Purpose(purpose) = param {
                Some(*purpose)
            } else {
                None
            }
        })
        .ok_or_else(|| km_err!(IncompatiblePurpose, "no purpose found for key!"))
}

fn check_ec_import_params(
    ec: &dyn Ec,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    let (key, curve) = match key_format {
        KeyFormat::Raw if get_ec_curve(params)? == EcCurve::Curve25519 => {
            if primary_purpose(params)? == KeyPurpose::AgreeKey {
                (
                    ec.import_raw_x25519_key(key_data, params)?,
                    EcCurve::Curve25519,
                )
            } else {
                (
                    ec.import_raw_ed25519_key(key_data, params)?,
                    EcCurve::Curve25519,
                )
            }
        }
        KeyFormat::Pkcs8 => {
            let key = ec.import_pkcs8_key(key_data, params)?;
            let curve = match &key {
                KeyMaterial::Ec(curve, CurveType::Nist, _) => *curve,
                KeyMaterial::Ec(EcCurve::Curve25519, CurveType::EdDsa, _) => {
                    if primary_purpose(params)? == KeyPurpose::AgreeKey {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "can't use EdDSA key for key agreement"
                        ));
                    }
                    EcCurve::Curve25519
                }
                KeyMaterial::Ec(EcCurve::Curve25519, CurveType::Xdh, _) => {
                    if primary_purpose(params)? != KeyPurpose::AgreeKey {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "can't use XDH key for signing"
                        ));
                    }
                    EcCurve::Curve25519
                }
                _ => {
                    return Err(km_err!(
                        ImportParameterMismatch,
                        "unexpected key type from EC import"
                    ))
                }
            };
            (key, curve)
        }
        _ => {
            return Err(km_err!(
                UnsupportedKeyFormat,
                "invalid import format ({:?}) for EC key",
                key_format,
            ));
        }
    };

    let mut deduced_chars = Vec::new();
    match get_opt_tag_value!(params, EcCurve)? {
        Some(specified_curve) => {
            if *specified_curve != curve {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "imported EC key claimed curve {:?} but is {:?}",
                    specified_curve,
                    curve
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::EcCurve(curve))?,
    }

    let key_size = ec::curve_to_key_size(curve);
    match get_opt_tag_value!(params, KeySize)? {
        Some(param_key_size) => {
            if *param_key_size != key_size {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified KEY_SIZE {:?} bits != actual key size {:?} for PKCS8 import",
                    param_key_size,
                    key_size
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::KeySize(key_size))?,
    }

    check_ec_params(curve, params, sec_level)?;
    Ok((deduced_chars, key))
}

fn check_ec_params(
    curve: EcCurve,
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<Option<KeyPurpose>, Error> {
    if sec_level == SecurityLevel::Strongbox && curve != EcCurve::P256 {
        return Err(km_err!(
            UnsupportedEcCurve,
            "invalid curve ({:?}) for StrongBox",
            curve
        ));
    }

    if let Some(key_size) = get_opt_tag_value!(params, KeySize)? {
        match curve {
            EcCurve::P224 if *key_size == KeySizeInBits(224) => {}
            EcCurve::P256 if *key_size == KeySizeInBits(256) => {}
            EcCurve::P384 if *key_size == KeySizeInBits(384) => {}
            EcCurve::P521 if *key_size == KeySizeInBits(521) => {}
            EcCurve::Curve25519 if *key_size == KeySizeInBits(256) => {}
            _ => {
                return Err(km_err!(
                    InvalidArgument,
                    "invalid curve ({:?}) / key size ({:?}) combination",
                    curve,
                    key_size
                ))
            }
        }
    }

    let mut seen_attest = false;
    let mut seen_sign = false;
    let mut seen_agree = false;
    let mut primary_purpose = None;
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign => seen_sign = true,
                KeyPurpose::AgreeKey => seen_agree = true,
                KeyPurpose::AttestKey => seen_attest = true,
                KeyPurpose::Verify => {}
                _ => warn!("Generating EC key with invalid purpose {purpose:?}"),
            }
            if primary_purpose.is_none() {
                primary_purpose = Some(*purpose);
            }
        }
    }

    if seen_attest && (seen_sign || seen_agree) {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }

    if curve == EcCurve::Curve25519 && seen_agree && (seen_sign || seen_attest) {
        return Err(km_err!(
            IncompatiblePurpose,
            "curve25519 keys must be either SIGN/ATTEST_KEY or AGREE_KEY, not both"
        ));
    }

    Ok(primary_purpose)
}

fn check_mldsa_import_params(
    mldsa: &dyn MlDsa,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    let specified_variant = get_opt_tag_value!(params, MlDsaVariant)?;
    let mut deduced_chars = Vec::new();
    let key = match key_format {
        KeyFormat::Raw => {
            let Some(variant) = specified_variant else {
                return Err(km_err!(InvalidArgument, "missing MlDsaVariant"));
            };
            mldsa.import_raw_key(key_data, *variant, params)?
        }
        KeyFormat::Pkcs8 => {
            let key = mldsa.import_pkcs8_key(key_data, params)?;
            let actual_variant = match &key {
                KeyMaterial::MlDsa(MlDsaVariant::MlDsa65, _) => MlDsaVariant::MlDsa65,
                KeyMaterial::MlDsa(MlDsaVariant::MlDsa87, _) => MlDsaVariant::MlDsa87,
                _ => {
                    return Err(km_err!(
                        ImportParameterMismatch,
                        "unexpected key type from ML-DSA import"
                    ))
                }
            };

            if let Some(specified_variant) = specified_variant {
                if *specified_variant != actual_variant {
                    return Err(km_err!(ImportParameterMismatch,
                                       "imported ML-DSA key claimed {specified_variant:?} but is {actual_variant:?}"));
                }
            }

            deduced_chars.try_push(KeyParam::MlDsaVariant(actual_variant))?;
            key
        }
        _ => {
            return Err(km_err!(
                UnsupportedKeyFormat,
                "unsupported import format {key_format:?}, expect RAW or PKCS8",
            ));
        }
    };

    check_mldsa_params(params, sec_level)?;
    Ok((deduced_chars, key))
}

fn check_mldsa_params(params: &[KeyParam], sec_level: SecurityLevel) -> Result<(), Error> {
    if sec_level == SecurityLevel::Strongbox {
        return Err(km_err!(
            UnsupportedAlgorithm,
            "ML-DSA not supported for StrongBox"
        ));
    }

    let mut seen_attest = false;
    let mut seen_sign = false;
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign => seen_sign = true,
                KeyPurpose::AttestKey => seen_attest = true,
                KeyPurpose::Verify => {}
                _ => warn!("Generating ML-DSA key with invalid purpose {purpose:?}"),
            }
        }
    }

    if seen_attest && seen_sign {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }

    Ok(())
}

fn check_aes_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;

    let keygen_info = match key_size {
        KeySizeInBits(128) => KeyGenInfo::Aes(aes::Variant::Aes128),
        KeySizeInBits(256) => KeyGenInfo::Aes(aes::Variant::Aes256),
        KeySizeInBits(192) if sec_level != SecurityLevel::Strongbox => {
            KeyGenInfo::Aes(aes::Variant::Aes192)
        }
        _ => {
            return Err(km_err!(
                UnsupportedKeySize,
                "unsupported KEY_SIZE {:?} bits for AES",
                key_size
            ))
        }
    };

    check_aes_params(params)?;
    Ok(keygen_info)
}

fn check_aes_import_params(
    aes: &dyn Aes,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    require_raw(key_format)?;
    let (key, key_size) = aes.import_key(key_data, params)?;
    if key_size == KeySizeInBits(192) && sec_level == SecurityLevel::Strongbox {
        return Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE=192 bits for AES on StrongBox",
        ));
    }
    let deduced_chars = require_matching_key_size(params, key_size)?;

    check_aes_params(params)?;
    Ok((deduced_chars, key))
}

fn check_aes_params(params: &[KeyParam]) -> Result<(), Error> {
    let gcm_support = params.contains(&KeyParam::BlockMode(BlockMode::Gcm));
    if gcm_support {
        let min_mac_len = get_tag_value!(params, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if (min_mac_len % 8 != 0) || !(96..=128).contains(&min_mac_len) {
            return Err(km_err!(
                UnsupportedMinMacLength,
                "unsupported MIN_MAC_LENGTH {} bits",
                min_mac_len
            ));
        }
    }
    Ok(())
}

fn check_3des_gen_params(params: &[KeyParam]) -> Result<KeyGenInfo, Error> {
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    if key_size != KeySizeInBits(168) {
        return Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE {:?} bits for TRIPLE_DES",
            key_size
        ));
    }
    Ok(KeyGenInfo::TripleDes)
}

fn check_3des_import_params(
    des: &dyn Des,
    params: &[KeyParam],
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    require_raw(key_format)?;
    let key = des.import_key(key_data, params)?;

    let deduced_chars = require_matching_key_size(params, des::KEY_SIZE_BITS)?;

    Ok((deduced_chars, key))
}

fn check_hmac_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    check_hmac_params(params, sec_level, key_size)?;
    Ok(KeyGenInfo::Hmac(key_size))
}

fn check_hmac_import_params(
    hmac: &dyn Hmac,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    require_raw(key_format)?;
    let (key, key_size) = hmac.import_key(key_data, params)?;
    let deduced_chars = require_matching_key_size(params, key_size)?;

    check_hmac_params(params, sec_level, key_size)?;
    Ok((deduced_chars, key))
}

fn check_hmac_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_size: KeySizeInBits,
) -> Result<(), Error> {
    if sec_level == SecurityLevel::Strongbox {
        hmac::valid_strongbox_hal_size(key_size)?;
    } else {
        hmac::valid_hal_size(key_size)?;
    }
    let digest = get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)?;
    if digest == Digest::None {
        return Err(km_err!(
            UnsupportedDigest,
            "unsupported digest {:?}",
            digest
        ));
    }

    let min_mac_len = get_tag_value!(params, MinMacLength, ErrorCode::MissingMinMacLength)?;
    if (min_mac_len % 8 != 0) || !(64..=512).contains(&min_mac_len) {
        return Err(km_err!(
            UnsupportedMinMacLength,
            "unsupported MIN_MAC_LENGTH {:?} bits",
            min_mac_len
        ));
    }
    Ok(())
}

fn require_raw(key_format: KeyFormat) -> Result<(), Error> {
    if key_format != KeyFormat::Raw {
        return Err(km_err!(
            UnsupportedKeyFormat,
            "unsupported import format {:?}, expect RAW",
            key_format
        ));
    }
    Ok(())
}

fn require_matching_key_size(
    params: &[KeyParam],
    key_size: KeySizeInBits,
) -> Result<Vec<KeyParam>, Error> {
    let mut deduced_chars = Vec::new();
    match get_opt_tag_value!(params, KeySize)? {
        Some(param_key_size) => {
            if *param_key_size != key_size {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified KEY_SIZE {:?} bits != actual key size {:?}",
                    param_key_size,
                    key_size
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::KeySize(key_size))?,
    }
    Ok(deduced_chars)
}

fn reject_incompatible_auth(params: &[KeyParam]) -> Result<(), Error> {
    let mut seen_user_secure_id = false;
    let mut seen_auth_type = false;
    let mut seen_no_auth = false;

    for param in params {
        match param {
            KeyParam::UserSecureId(_sid) => seen_user_secure_id = true,
            KeyParam::UserAuthType(_atype) => seen_auth_type = true,
            KeyParam::NoAuthRequired => seen_no_auth = true,
            _ => {}
        }
    }

    if seen_no_auth {
        if seen_user_secure_id {
            return Err(km_err!(
                InvalidTag,
                "found both NO_AUTH_REQUIRED and USER_SECURE_ID"
            ));
        }
        if seen_auth_type {
            return Err(km_err!(
                InvalidTag,
                "found both NO_AUTH_REQUIRED and USER_AUTH_TYPE"
            ));
        }
    }
    if seen_user_secure_id && !seen_auth_type {
        return Err(km_err!(
            InvalidTag,
            "found USER_SECURE_ID but no USER_AUTH_TYPE"
        ));
    }
    Ok(())
}

pub fn digest_len(digest: Digest) -> Result<u32, Error> {
    match digest {
        Digest::Md5 => Ok(128),
        Digest::Sha1 => Ok(160),
        Digest::Sha224 => Ok(224),
        Digest::Sha256 => Ok(256),
        Digest::Sha384 => Ok(384),
        Digest::Sha512 => Ok(512),
        _ => Err(km_err!(IncompatibleDigest, "invalid digest {:?}", digest)),
    }
}

pub fn check_rsa_wrapping_key_params(
    chars: &[KeyParam],
    params: &[KeyParam],
) -> Result<DecryptionMode, Error> {
    if !contains_tag_value!(chars, Purpose, KeyPurpose::WrapKey) {
        return Err(km_err!(
            IncompatiblePurpose,
            "no wrap key purpose for the wrapping key"
        ));
    }
    let padding_mode = get_tag_value!(params, Padding, ErrorCode::IncompatiblePaddingMode)?;
    if padding_mode != PaddingMode::RsaOaep {
        return Err(km_err!(
            IncompatiblePaddingMode,
            "invalid padding mode {:?} for RSA wrapping key",
            padding_mode
        ));
    }
    let msg_digest = get_tag_value!(params, Digest, ErrorCode::IncompatibleDigest)?;
    if msg_digest != Digest::Sha256 {
        return Err(km_err!(
            IncompatibleDigest,
            "invalid digest {:?} for RSA wrapping key",
            padding_mode
        ));
    }
    let opt_mgf_digest = get_opt_tag_value!(params, RsaOaepMgfDigest)?;
    if opt_mgf_digest == Some(&Digest::None) {
        return Err(km_err!(
            UnsupportedMgfDigest,
            "MGF digest cannot be NONE for RSA-OAEP"
        ));
    }

    if !contains_tag_value!(chars, Padding, padding_mode) {
        return Err(km_err!(
            IncompatiblePaddingMode,
            "padding mode {:?} not in key characteristics {:?}",
            padding_mode,
            chars,
        ));
    }
    if !contains_tag_value!(chars, Digest, msg_digest) {
        return Err(km_err!(
            IncompatibleDigest,
            "digest {:?} not in key characteristics {:?}",
            msg_digest,
            chars,
        ));
    }

    if let Some(mgf_digest) = opt_mgf_digest {
        if !contains_tag_value!(chars, RsaOaepMgfDigest, *mgf_digest) {
            return Err(km_err!(
                IncompatibleDigest,
                "MGF digest {:?} not in key characteristics {:?}",
                mgf_digest,
                chars,
            ));
        }
    }
    let mgf_digest = opt_mgf_digest.unwrap_or(&Digest::Sha1);

    let rsa_oaep_decrypt_mode = DecryptionMode::OaepPadding {
        msg_digest,
        mgf_digest: *mgf_digest,
    };
    Ok(rsa_oaep_decrypt_mode)
}

fn luhn_checksum(mut val: u64) -> u64 {
    let mut ii = 0;
    let mut sum_digits = 0;
    while val != 0 {
        let curr_digit = val % 10;
        let multiplier = if ii % 2 == 0 { 2 } else { 1 };
        let digit_multiplied = curr_digit * multiplier;
        sum_digits += (digit_multiplied % 10) + (digit_multiplied / 10);
        val /= 10;
        ii += 1;
    }
    (10 - (sum_digits % 10)) % 10
}

pub fn increment_imei(imei: &[u8]) -> Vec<u8> {
    if imei.is_empty() {
        info!("empty IMEI");
        return Vec::new();
    }

    let imei: &str = match core::str::from_utf8(imei) {
        Ok(v) => v,
        Err(_) => {
            warn!("IMEI is not UTF-8");
            return Vec::new();
        }
    };

    let imei: u64 = match imei.parse() {
        Ok(v) => v,
        Err(_) => {
            warn!("IMEI is not numeric");
            return Vec::new();
        }
    };

    let imei2 = (imei / 10) + 1;
    let imei2_without_checksum = match imei2.checked_mul(10) {
        Some(v) => v,
        None => {
            warn!("IMEI overflow");
            return Vec::new();
        }
    };
    let imei2 = imei2_without_checksum + luhn_checksum(imei2);

    std::format!("{imei2}").into_bytes()
}
