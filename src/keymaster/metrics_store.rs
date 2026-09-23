// Copyright 2021, The Android Open Source Project
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
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter, KeyPurpose::KeyPurpose, MlDsaVariant::MlDsaVariant,
    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
};
use crate::android::security::metrics::{
    Algorithm::Algorithm as MetricsAlgorithm, AtomID::AtomID, CrashStats::CrashStats,
    EcCurve::EcCurve as MetricsEcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType as MetricsHardwareAuthenticatorType,
    KeyCreationPerUid::KeyCreationPerUid, KeyCreationWithAuthInfo::KeyCreationWithAuthInfo,
    KeyCreationWithGeneralInfo::KeyCreationWithGeneralInfo,
    KeyCreationWithPurposeAndModesInfo::KeyCreationWithPurposeAndModesInfo,
    KeyOperationPerUid::KeyOperationPerUid, KeyOperationStreamingStats::KeyOperationStreamingStats,
    KeyOperationWithGeneralInfo::KeyOperationWithGeneralInfo,
    KeyOperationWithPurposeAndModesInfo::KeyOperationWithPurposeAndModesInfo,
    KeyOrigin::KeyOrigin as MetricsKeyOrigin, KeysPerUid::KeysPerUid,
    Keystore2AtomWithOverflow::Keystore2AtomWithOverflow, KeystoreAtom::KeystoreAtom,
    KeystoreAtomPayload::KeystoreAtomPayload, OperationLatency::OperationLatency,
    OperationType::OperationType as MetricsOperationType, Outcome::Outcome as MetricsOutcome,
    Purpose::Purpose as MetricsPurpose, RkpError::RkpError as MetricsRkpError,
    SecurityLevel::SecurityLevel as MetricsSecurityLevel, Storage::Storage as MetricsStorage,
};
use crate::err as ks_err;
use crate::global::DB;
use crate::keymaster::error::anyhow_error_to_serialized_error;
use crate::keymaster::key_parameter::KeyParameterValue as KsKeyParamValue;
use crate::keymaster::operation::Outcome;
use crate::watchdog as wd;
use anyhow::{anyhow, Context, Result};
use log::{error, warn};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

#[macro_export]
macro_rules! timed_call {
    ($f:expr) => {{
        let start = std::time::Instant::now();
        let result = $f;
        (start.elapsed(), result)
    }};
}

#[cfg(test)]
mod tests;

const KEYSTORE_CRASH_COUNT_PATH: &str = crate::root_path!("crash_count");
const KERNEL_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

pub const KEYS_PER_UID_MAX_UIDS: usize = 10;

pub const KEYS_PER_UID_MIN_KEY_COUNT: usize = 5;

pub static METRICS_STORE: LazyLock<MetricsStore> = LazyLock::new(Default::default);

#[derive(Default)]
pub struct MetricsStore {
    metrics_store: Mutex<HashMap<AtomID, HashMap<KeystoreAtomPayload, i32>>>,
}

impl std::fmt::Debug for MetricsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let store = self.metrics_store.lock().unwrap();
        let mut atom_ids: Vec<&AtomID> = store.keys().collect();
        atom_ids.sort();
        for atom_id in atom_ids {
            writeln!(f, "  {} : [", atom_id.show())?;
            let data = store.get(atom_id).unwrap();
            let mut payloads: Vec<&KeystoreAtomPayload> = data.keys().collect();
            payloads.sort();
            for payload in payloads {
                let count = data.get(payload).unwrap();
                writeln!(f, "    {} => count={count}", payload.show())?;
            }
            writeln!(f, "  ]")?;
        }
        Ok(())
    }
}

impl MetricsStore {
    const SINGLE_ATOM_STORE_MAX_SIZE: usize = 250;

    pub fn get_atoms(&self, atom_id: AtomID) -> Result<Vec<KeystoreAtom>> {
        match atom_id {
            AtomID::STORAGE_STATS => {
                let _wp = wd::watch("MetricsStore::get_atoms calling pull_storage_stats");
                pull_storage_stats()
            }
            AtomID::KEYS_PER_UID => {
                let _wp = wd::watch("MetricsStore::get_atoms calling pull_keys_per_uid");
                pull_keys_per_uid()
            }
            AtomID::CRASH_STATS => {
                let _wp = wd::watch("MetricsStore::get_atoms calling read_keystore_crash_count");
                match read_keystore_crash_count()? {
                    Some(count) => Ok(vec![KeystoreAtom {
                        payload: KeystoreAtomPayload::CrashStats(CrashStats {
                            count_of_crash_events: count,
                        }),
                        ..Default::default()
                    }]),
                    None => Err(anyhow!("Crash count file is not set")),
                }
            }
            AtomID::KEY_CREATION_WITH_GENERAL_INFO
            | AtomID::KEY_CREATION_WITH_AUTH_INFO
            | AtomID::KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO
            | AtomID::KEYSTORE2_ATOM_WITH_OVERFLOW
            | AtomID::KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO
            | AtomID::KEY_OPERATION_WITH_GENERAL_INFO
            | AtomID::KEY_CREATION_PER_UID
            | AtomID::KEY_OPERATION_PER_UID
            | AtomID::RKP_ERROR_STATS
            | AtomID::OPERATION_LATENCY
            | AtomID::KEY_OPERATION_STREAMING_STATS => {
                let metrics_store_guard = self.metrics_store.lock().unwrap();
                metrics_store_guard.get(&atom_id).map_or(
                    Ok(Vec::<KeystoreAtom>::new()),
                    |atom_count_map| {
                        Ok(atom_count_map
                            .iter()
                            .map(|(atom, count)| KeystoreAtom {
                                payload: atom.clone(),
                                count: *count,
                            })
                            .collect())
                    },
                )
            }
            _ => Err(anyhow!(
                "MetricsStore::get_atoms: Unrecognized AtomID {:?}",
                atom_id
            )),
        }
    }

    fn insert_atom(&self, atom_id: AtomID, atom: KeystoreAtomPayload) {
        let mut metrics_store_guard = self.metrics_store.lock().unwrap();
        let atom_count_map = metrics_store_guard.entry(atom_id).or_default();
        if atom_count_map.len() < MetricsStore::SINGLE_ATOM_STORE_MAX_SIZE {
            let atom_count = atom_count_map.entry(atom).or_insert(0);
            *atom_count += 1;
        } else {
            let overflow_atom_count_map = metrics_store_guard
                .entry(AtomID::KEYSTORE2_ATOM_WITH_OVERFLOW)
                .or_default();

            if overflow_atom_count_map.len() < MetricsStore::SINGLE_ATOM_STORE_MAX_SIZE {
                let overflow_atom = Keystore2AtomWithOverflow { atom_id };
                let atom_count = overflow_atom_count_map
                    .entry(KeystoreAtomPayload::Keystore2AtomWithOverflow(
                        overflow_atom,
                    ))
                    .or_insert(0);
                *atom_count += 1;
            } else {
                error!("In insert_atom: Maximum storage limit reached for overflow atom.")
            }
        }
    }
}

pub fn log_key_creation_event_stats<U>(
    uid: i32,
    sec_level: SecurityLevel,
    key_params: &[KeyParameter],
    origin: KeyOrigin,
    result: &Result<U>,
) {
    let (
        key_creation_with_general_info,
        key_creation_with_auth_info,
        key_creation_with_purpose_and_modes_info,
        key_creation_per_uid,
    ) = process_key_creation_event_stats(uid, sec_level, key_params, origin, result);

    METRICS_STORE.insert_atom(
        AtomID::KEY_CREATION_WITH_GENERAL_INFO,
        key_creation_with_general_info,
    );
    METRICS_STORE.insert_atom(
        AtomID::KEY_CREATION_WITH_AUTH_INFO,
        key_creation_with_auth_info,
    );
    METRICS_STORE.insert_atom(
        AtomID::KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO,
        key_creation_with_purpose_and_modes_info,
    );
    if crate::keymaster::flags::atoms_v2() {
        METRICS_STORE.insert_atom(AtomID::KEY_CREATION_PER_UID, key_creation_per_uid);
    }
}

fn process_key_creation_event_stats<U>(
    uid: i32,
    sec_level: SecurityLevel,
    key_params: &[KeyParameter],
    origin: KeyOrigin,
    result: &Result<U>,
) -> (
    KeystoreAtomPayload,
    KeystoreAtomPayload,
    KeystoreAtomPayload,
    KeystoreAtomPayload,
) {
    let mut key_creation_with_general_info = KeyCreationWithGeneralInfo {
        algorithm: MetricsAlgorithm::ALGORITHM_UNSPECIFIED,
        key_size: -1,
        ec_curve: MetricsEcCurve::EC_CURVE_UNSPECIFIED,
        key_origin: match origin {
            KeyOrigin::GENERATED => MetricsKeyOrigin::GENERATED,
            KeyOrigin::DERIVED => MetricsKeyOrigin::DERIVED,
            KeyOrigin::IMPORTED => MetricsKeyOrigin::IMPORTED,
            KeyOrigin::RESERVED => MetricsKeyOrigin::RESERVED,
            KeyOrigin::SECURELY_IMPORTED => MetricsKeyOrigin::SECURELY_IMPORTED,
            _ => MetricsKeyOrigin::ORIGIN_UNSPECIFIED,
        },
        error_code: 1,

        ..Default::default()
    };

    let mut key_creation_with_auth_info = KeyCreationWithAuthInfo {
        user_auth_type: MetricsHardwareAuthenticatorType::NO_AUTH_TYPE,
        log10_auth_key_timeout_seconds: -1,
        security_level: MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
    };

    let mut key_creation_with_purpose_and_modes_info = KeyCreationWithPurposeAndModesInfo {
        algorithm: MetricsAlgorithm::ALGORITHM_UNSPECIFIED,

        ..Default::default()
    };

    if let Err(ref e) = result {
        key_creation_with_general_info.error_code = anyhow_error_to_serialized_error(e).0;
    }

    key_creation_with_auth_info.security_level = process_security_level(sec_level);

    let (algorithm, key_size, ec_curve) = parse_key_parameters(key_params);
    let key_size = key_size.unwrap_or(-1);
    key_creation_with_purpose_and_modes_info.algorithm = algorithm;
    key_creation_with_general_info.algorithm = algorithm;
    key_creation_with_general_info.key_size = key_size;
    key_creation_with_general_info.ec_curve = ec_curve;

    for key_param in key_params.iter().map(KsKeyParamValue::from) {
        match key_param {
            KsKeyParamValue::HardwareAuthenticatorType(a) => {
                key_creation_with_auth_info.user_auth_type = match a {
                    HardwareAuthenticatorType::NONE => MetricsHardwareAuthenticatorType::NONE,
                    HardwareAuthenticatorType::PASSWORD => {
                        MetricsHardwareAuthenticatorType::PASSWORD
                    }
                    HardwareAuthenticatorType::FINGERPRINT => {
                        MetricsHardwareAuthenticatorType::FINGERPRINT
                    }
                    a if a.0
                        == HardwareAuthenticatorType::PASSWORD.0
                            | HardwareAuthenticatorType::FINGERPRINT.0 =>
                    {
                        MetricsHardwareAuthenticatorType::PASSWORD_OR_FINGERPRINT
                    }
                    HardwareAuthenticatorType::ANY => MetricsHardwareAuthenticatorType::ANY,
                    _ => MetricsHardwareAuthenticatorType::AUTH_TYPE_UNSPECIFIED,
                }
            }
            KsKeyParamValue::AuthTimeout(t) => {
                key_creation_with_auth_info.log10_auth_key_timeout_seconds =
                    f32::log10(t as f32) as i32;
            }
            KsKeyParamValue::PaddingMode(p) => {
                compute_padding_mode_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.padding_mode_bitmap,
                    p,
                );
            }
            KsKeyParamValue::Digest(d) => {
                compute_digest_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.digest_bitmap,
                    d,
                );
            }
            KsKeyParamValue::BlockMode(b) => {
                compute_block_mode_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.block_mode_bitmap,
                    b,
                );
            }
            KsKeyParamValue::KeyPurpose(k) => {
                compute_purpose_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.purpose_bitmap,
                    k,
                );
            }
            KsKeyParamValue::AttestationChallenge(_) => {
                key_creation_with_general_info.attestation_requested = true;
            }
            _ => {}
        }
    }

    let key_creation_per_uid = KeyCreationPerUid {
        uid,
        security_level: key_creation_with_auth_info.security_level,
        algorithm,
        user_auth_type: key_creation_with_auth_info.user_auth_type,
        attestation_requested: key_creation_with_general_info.attestation_requested,
    };

    (
        KeystoreAtomPayload::KeyCreationWithGeneralInfo(key_creation_with_general_info),
        KeystoreAtomPayload::KeyCreationWithAuthInfo(key_creation_with_auth_info),
        KeystoreAtomPayload::KeyCreationWithPurposeAndModesInfo(
            key_creation_with_purpose_and_modes_info,
        ),
        KeystoreAtomPayload::KeyCreationPerUid(key_creation_per_uid),
    )
}

pub fn log_key_operation_event_stats(
    uid: i32,
    sec_level: SecurityLevel,
    key_purpose: KeyPurpose,
    op_params: &[KeyParameter],
    op_outcome: &Outcome,
    key_upgraded: bool,
    is_attested: bool,
) {
    let (
        key_operation_with_general_info,
        key_operation_with_purpose_and_modes_info,
        key_operation_per_uid,
    ) = process_key_operation_event_stats(
        uid,
        sec_level,
        key_purpose,
        op_params,
        op_outcome,
        key_upgraded,
        is_attested,
    );
    METRICS_STORE.insert_atom(
        AtomID::KEY_OPERATION_WITH_GENERAL_INFO,
        key_operation_with_general_info,
    );
    METRICS_STORE.insert_atom(
        AtomID::KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO,
        key_operation_with_purpose_and_modes_info,
    );
    if crate::keymaster::flags::atoms_v2() {
        METRICS_STORE.insert_atom(AtomID::KEY_OPERATION_PER_UID, key_operation_per_uid);
    }
}

fn process_key_operation_event_stats(
    uid: i32,
    sec_level: SecurityLevel,
    key_purpose: KeyPurpose,
    op_params: &[KeyParameter],
    op_outcome: &Outcome,
    key_upgraded: bool,
    is_attested: bool,
) -> (
    KeystoreAtomPayload,
    KeystoreAtomPayload,
    KeystoreAtomPayload,
) {
    let security_level = process_security_level(sec_level);
    let key_operation_per_uid = KeyOperationPerUid {
        uid,
        security_level,
    };

    let mut key_operation_with_general_info = KeyOperationWithGeneralInfo {
        outcome: MetricsOutcome::OUTCOME_UNSPECIFIED,
        error_code: 1,
        security_level,
        is_attested,

        ..Default::default()
    };

    let mut key_operation_with_purpose_and_modes_info = KeyOperationWithPurposeAndModesInfo {
        purpose: MetricsPurpose::KEY_PURPOSE_UNSPECIFIED,

        ..Default::default()
    };

    key_operation_with_general_info.key_upgraded = key_upgraded;

    key_operation_with_purpose_and_modes_info.purpose = match key_purpose {
        KeyPurpose::ENCRYPT => MetricsPurpose::ENCRYPT,
        KeyPurpose::DECRYPT => MetricsPurpose::DECRYPT,
        KeyPurpose::SIGN => MetricsPurpose::SIGN,
        KeyPurpose::VERIFY => MetricsPurpose::VERIFY,
        KeyPurpose::WRAP_KEY => MetricsPurpose::WRAP_KEY,
        KeyPurpose::AGREE_KEY => MetricsPurpose::AGREE_KEY,
        KeyPurpose::ATTEST_KEY => MetricsPurpose::ATTEST_KEY,
        _ => MetricsPurpose::KEY_PURPOSE_UNSPECIFIED,
    };

    key_operation_with_general_info.outcome = match op_outcome {
        Outcome::Unknown | Outcome::Dropped => MetricsOutcome::DROPPED,
        Outcome::Success => MetricsOutcome::SUCCESS,
        Outcome::Abort => MetricsOutcome::ABORT,
        Outcome::Pruned => MetricsOutcome::PRUNED,
        Outcome::ErrorCode(e) => {
            key_operation_with_general_info.error_code = e.0;
            MetricsOutcome::ERROR
        }
    };

    for key_param in op_params.iter().map(KsKeyParamValue::from) {
        match key_param {
            KsKeyParamValue::PaddingMode(p) => {
                compute_padding_mode_bitmap(
                    &mut key_operation_with_purpose_and_modes_info.padding_mode_bitmap,
                    p,
                );
            }
            KsKeyParamValue::Digest(d) => {
                compute_digest_bitmap(
                    &mut key_operation_with_purpose_and_modes_info.digest_bitmap,
                    d,
                );
            }
            KsKeyParamValue::BlockMode(b) => {
                compute_block_mode_bitmap(
                    &mut key_operation_with_purpose_and_modes_info.block_mode_bitmap,
                    b,
                );
            }
            _ => {}
        }
    }

    (
        KeystoreAtomPayload::KeyOperationWithGeneralInfo(key_operation_with_general_info),
        KeystoreAtomPayload::KeyOperationWithPurposeAndModesInfo(
            key_operation_with_purpose_and_modes_info,
        ),
        KeystoreAtomPayload::KeyOperationPerUid(key_operation_per_uid),
    )
}

fn process_security_level(sec_level: SecurityLevel) -> MetricsSecurityLevel {
    match sec_level {
        SecurityLevel::SOFTWARE => MetricsSecurityLevel::SECURITY_LEVEL_SOFTWARE,
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            MetricsSecurityLevel::SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }
        SecurityLevel::STRONGBOX => MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX,
        SecurityLevel::KEYSTORE => MetricsSecurityLevel::SECURITY_LEVEL_KEYSTORE,
        _ => MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
    }
}

fn compute_padding_mode_bitmap(padding_mode_bitmap: &mut i32, padding_mode: PaddingMode) {
    match padding_mode {
        PaddingMode::NONE => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::NONE_BIT_POSITION as i32;
        }
        PaddingMode::RSA_OAEP => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::RSA_OAEP_BIT_POS as i32;
        }
        PaddingMode::RSA_PSS => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::RSA_PSS_BIT_POS as i32;
        }
        PaddingMode::RSA_PKCS1_1_5_ENCRYPT => {
            *padding_mode_bitmap |=
                1 << PaddingModeBitPosition::RSA_PKCS1_1_5_ENCRYPT_BIT_POS as i32;
        }
        PaddingMode::RSA_PKCS1_1_5_SIGN => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::RSA_PKCS1_1_5_SIGN_BIT_POS as i32;
        }
        PaddingMode::PKCS7 => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::PKCS7_BIT_POS as i32;
        }
        _ => {}
    }
}

fn compute_digest_bitmap(digest_bitmap: &mut i32, digest: Digest) {
    match digest {
        Digest::NONE => {
            *digest_bitmap |= 1 << DigestBitPosition::NONE_BIT_POSITION as i32;
        }
        Digest::MD5 => {
            *digest_bitmap |= 1 << DigestBitPosition::MD5_BIT_POS as i32;
        }
        Digest::SHA1 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_1_BIT_POS as i32;
        }
        Digest::SHA_2_224 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_224_BIT_POS as i32;
        }
        Digest::SHA_2_256 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_256_BIT_POS as i32;
        }
        Digest::SHA_2_384 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_384_BIT_POS as i32;
        }
        Digest::SHA_2_512 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_512_BIT_POS as i32;
        }
        _ => {}
    }
}

fn compute_block_mode_bitmap(block_mode_bitmap: &mut i32, block_mode: BlockMode) {
    match block_mode {
        BlockMode::ECB => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::ECB_BIT_POS as i32;
        }
        BlockMode::CBC => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::CBC_BIT_POS as i32;
        }
        BlockMode::CTR => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::CTR_BIT_POS as i32;
        }
        BlockMode::GCM => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::GCM_BIT_POS as i32;
        }
        _ => {}
    }
}

fn compute_purpose_bitmap(purpose_bitmap: &mut i32, purpose: KeyPurpose) {
    match purpose {
        KeyPurpose::ENCRYPT => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::ENCRYPT_BIT_POS as i32;
        }
        KeyPurpose::DECRYPT => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::DECRYPT_BIT_POS as i32;
        }
        KeyPurpose::SIGN => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::SIGN_BIT_POS as i32;
        }
        KeyPurpose::VERIFY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::VERIFY_BIT_POS as i32;
        }
        KeyPurpose::WRAP_KEY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::WRAP_KEY_BIT_POS as i32;
        }
        KeyPurpose::AGREE_KEY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::AGREE_KEY_BIT_POS as i32;
        }
        KeyPurpose::ATTEST_KEY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::ATTEST_KEY_BIT_POS as i32;
        }
        _ => {}
    }
}

pub(crate) fn pull_storage_stats() -> Result<Vec<KeystoreAtom>> {
    let mut atom_vec: Vec<KeystoreAtom> = Vec::new();
    let mut append = |stat| {
        match stat {
            Ok(s) => atom_vec.push(KeystoreAtom {
                payload: KeystoreAtomPayload::StorageStats(s),
                ..Default::default()
            }),
            Err(error) => {
                error!("pull_metrics_callback: Error getting storage stat: {error}")
            }
        };
    };
    DB.with(|db| {
        let mut db = db.borrow_mut();
        append(db.get_storage_stat(MetricsStorage::DATABASE));
        append(db.get_storage_stat(MetricsStorage::KEY_ENTRY));
        append(db.get_storage_stat(MetricsStorage::KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX));
        append(db.get_storage_stat(MetricsStorage::BLOB_ENTRY));
        append(db.get_storage_stat(MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::KEY_PARAMETER));
        append(db.get_storage_stat(MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::KEY_METADATA));
        append(db.get_storage_stat(MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::GRANT));
        append(db.get_storage_stat(MetricsStorage::AUTH_TOKEN));
        append(db.get_storage_stat(MetricsStorage::BLOB_METADATA));
        append(db.get_storage_stat(MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX));
    });
    Ok(atom_vec)
}

fn pull_keys_per_uid() -> Result<Vec<KeystoreAtom>> {
    let counts = DB.with(|db| {
        let mut db = db.borrow_mut();
        db.per_uid_counts(KEYS_PER_UID_MAX_UIDS, KEYS_PER_UID_MIN_KEY_COUNT)
            .unwrap_or_else(|e| {
                error!("pull_keys_per_uid: failed to retrieve top per-UID key counts: {e:?}");
                Vec::new()
            })
    });
    Ok(counts
        .into_iter()
        .map(|(uid, count)| {
            let key_count: i32 = count.try_into().unwrap_or_else(|e| {
                error!("pull_keys_per_uid: key count {count} for {uid} out of range: {e:?}");
                i32::MAX
            });
            let s = KeysPerUid { uid, key_count };
            KeystoreAtom {
                payload: KeystoreAtomPayload::KeysPerUid(s),
                ..Default::default()
            }
        })
        .collect())
}

pub(crate) fn parse_key_parameters(
    params: &[KeyParameter],
) -> (MetricsAlgorithm, Option<i32>, MetricsEcCurve) {
    let mut algorithm = MetricsAlgorithm::ALGORITHM_UNSPECIFIED;
    let mut key_size = None;
    let mut ec_curve = MetricsEcCurve::EC_CURVE_UNSPECIFIED;

    for p in params.iter().map(KsKeyParamValue::from) {
        match p {
            KsKeyParamValue::Algorithm(alg) => {
                algorithm = match alg {
                    Algorithm::RSA => MetricsAlgorithm::RSA,
                    Algorithm::EC => MetricsAlgorithm::EC,
                    Algorithm::AES => MetricsAlgorithm::AES,
                    Algorithm::TRIPLE_DES => MetricsAlgorithm::TRIPLE_DES,
                    Algorithm::HMAC => MetricsAlgorithm::HMAC,

                    Algorithm::ML_DSA => algorithm,
                    _ => MetricsAlgorithm::ALGORITHM_UNSPECIFIED,
                };
            }
            KsKeyParamValue::MlDsaVariant(v) => {
                algorithm = match v {
                    MlDsaVariant::ML_DSA_65 => MetricsAlgorithm::ML_DSA_65,
                    MlDsaVariant::ML_DSA_87 => MetricsAlgorithm::ML_DSA_87,
                    _ => algorithm,
                };
            }
            KsKeyParamValue::KeySize(sz) => {
                key_size = Some(sz);
            }
            KsKeyParamValue::EcCurve(curve) => {
                ec_curve = match curve {
                    EcCurve::P_224 => MetricsEcCurve::P_224,
                    EcCurve::P_256 => MetricsEcCurve::P_256,
                    EcCurve::P_384 => MetricsEcCurve::P_384,
                    EcCurve::P_521 => MetricsEcCurve::P_521,
                    EcCurve::CURVE_25519 => MetricsEcCurve::CURVE_25519,
                    _ => MetricsEcCurve::EC_CURVE_UNSPECIFIED,
                };
            }
            _ => {}
        }
    }

    if algorithm == MetricsAlgorithm::EC {
        key_size = None;
    }

    (algorithm, key_size, ec_curve)
}

pub fn log_operation_latency(
    op_type: MetricsOperationType,
    sec_level: SecurityLevel,
    params: &[KeyParameter],
    is_success: bool,
    latency: Duration,
) {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let (algorithm, key_size, ec_curve) = parse_key_parameters(params);
    if algorithm == MetricsAlgorithm::ALGORITHM_UNSPECIFIED {
        warn!("Unknown algorithm in log_operation_latency - skipping metrics");
        return;
    }
    let key_size = key_size.unwrap_or(-1);
    let security_level = process_security_level(sec_level);
    let latency_ms = round_latency(latency);

    METRICS_STORE.insert_atom(
        AtomID::OPERATION_LATENCY,
        KeystoreAtomPayload::OperationLatency(OperationLatency {
            operation_type: op_type,
            algorithm,
            key_size,
            ec_curve,
            security_level,
            is_success,
            latency_ms,
        }),
    );
}

pub fn log_key_operation_streaming_stats(
    algorithm: MetricsAlgorithm,
    is_success: bool,
    call_count: i32,
    total_input_bytes: u64,
) {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }
    METRICS_STORE.insert_atom(
        AtomID::KEY_OPERATION_STREAMING_STATS,
        KeystoreAtomPayload::KeyOperationStreamingStats(KeyOperationStreamingStats {
            algorithm,
            is_success,
            call_count: round_logarithmic(call_count as u64, 10, 1, 20) as i32,
            total_input_bytes: round_logarithmic(total_input_bytes, 10, 1, 0),
        }),
    );
}

fn round_logarithmic(
    val: u64,
    buckets_per_decade: u32,
    min_step: u64,
    no_round_threshold: u64,
) -> i64 {
    if val <= no_round_threshold {
        return val as i64;
    }
    let exponent = val.ilog10();
    let step = 10u64.pow(exponent + 1) / (buckets_per_decade as u64);
    let step = std::cmp::max(step, min_step);
    let rounded = (val + step / 2) / step * step;
    std::cmp::min(rounded, i64::MAX as u64) as i64
}

fn round_latency(latency: std::time::Duration) -> i32 {
    let ms = latency.as_millis().clamp(0, i32::MAX as u128) as u32;
    let step = match ms {
        0..=10 => 5,
        11..=100 => 10,
        _ => 10u32.pow(ms.ilog10()) / 2,
    };
    let rounded_ms = (ms + step / 2) / step * step;
    rounded_ms as i32
}

pub fn update_keystore_crash_count() {
    let boot_id = match current_boot_id() {
        Ok(boot_id) => boot_id,
        Err(error) => {
            warn!(
                "failed to read boot ID while updating keystore crash count: {error:?}; keystore crashes will not be logged"
            );
            return;
        }
    };

    let new_count = match read_keystore_crash_count_for_boot(&boot_id) {
        Ok(Some(count)) => count + 1,

        Ok(None) => 0,
        Err(error) => {
            warn!(
                concat!(
                    "failed to read existing keystore crash count: {:?}; ",
                    "keystore crashes will not be logged"
                ),
                error
            );
            return;
        }
    };

    if let Err(e) = std::fs::write(
        KEYSTORE_CRASH_COUNT_PATH,
        format!("{boot_id}\n{new_count}\n"),
    ) {
        error!("failed to write keystore crash count file: {e:?}");
    }
}

pub fn read_keystore_crash_count() -> Result<Option<i32>> {
    let boot_id = current_boot_id()?;
    read_keystore_crash_count_for_boot(&boot_id)
}

fn read_keystore_crash_count_for_boot(boot_id: &str) -> Result<Option<i32>> {
    match std::fs::read_to_string(KEYSTORE_CRASH_COUNT_PATH) {
        Ok(record) => parse_crash_count_record(&record, boot_id),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context(ks_err!("Failed to read crash count file.")),
    }
}

fn current_boot_id() -> Result<String> {
    std::fs::read_to_string(KERNEL_BOOT_ID_PATH)
        .map(|boot_id| boot_id.trim().to_string())
        .context(ks_err!("Failed to read boot ID."))
}

fn parse_crash_count_record(record: &str, current_boot_id: &str) -> Result<Option<i32>> {
    let mut lines = record.lines();
    let Some(boot_id) = lines.next().map(str::trim).filter(|line| !line.is_empty()) else {
        return Ok(None);
    };
    let Some(count) = lines.next().map(str::trim).filter(|line| !line.is_empty()) else {
        return Err(anyhow!("crash count record has no count"));
    };

    if boot_id != current_boot_id {
        return Ok(None);
    }

    let count = count
        .parse::<i32>()
        .context(ks_err!("Failed to parse crash count."))?;
    if count < 0 {
        return Err(anyhow!("crash count is negative"));
    }
    Ok(Some(count))
}

#[allow(non_camel_case_types)]
#[repr(i32)]
enum PaddingModeBitPosition {
    NONE_BIT_POSITION = 0,

    RSA_OAEP_BIT_POS = 1,

    RSA_PSS_BIT_POS = 2,

    RSA_PKCS1_1_5_ENCRYPT_BIT_POS = 3,

    RSA_PKCS1_1_5_SIGN_BIT_POS = 4,

    PKCS7_BIT_POS = 5,
}

#[allow(non_camel_case_types)]
#[repr(i32)]
enum DigestBitPosition {
    NONE_BIT_POSITION = 0,

    MD5_BIT_POS = 1,

    SHA_1_BIT_POS = 2,

    SHA_2_224_BIT_POS = 3,

    SHA_2_256_BIT_POS = 4,

    SHA_2_384_BIT_POS = 5,

    SHA_2_512_BIT_POS = 6,
}

#[allow(non_camel_case_types)]
#[repr(i32)]
enum BlockModeBitPosition {
    ECB_BIT_POS = 1,

    CBC_BIT_POS = 2,

    CTR_BIT_POS = 3,

    GCM_BIT_POS = 4,
}

#[allow(non_camel_case_types)]
#[repr(i32)]
enum KeyPurposeBitPosition {
    ENCRYPT_BIT_POS = 1,

    DECRYPT_BIT_POS = 2,

    SIGN_BIT_POS = 3,

    VERIFY_BIT_POS = 4,

    WRAP_KEY_BIT_POS = 5,

    AGREE_KEY_BIT_POS = 6,

    ATTEST_KEY_BIT_POS = 7,
}

trait Summary {
    fn show(&self) -> String;
}

macro_rules! impl_summary_enum {
    {  $enum:ident, $width:literal, $( $variant:ident => $short:literal ),+ $(,)? } => {
        impl Summary for $enum{
            fn show(&self) -> String {
                match self.0 {
                    $(
                        x if x == Self::$variant.0 => format!(concat!("{:",
                                                                      stringify!($width),
                                                                      "}"),
                                                              $short),
                    )*
                    v => format!("Unknown({})", v),
                }
            }
        }
    }
}

impl_summary_enum!(AtomID, 14,
    STORAGE_STATS => "STORAGE",
    KEYSTORE2_ATOM_WITH_OVERFLOW => "OVERFLOW",
    KEY_CREATION_WITH_GENERAL_INFO => "KEYGEN_GENERAL",
    KEY_CREATION_WITH_AUTH_INFO => "KEYGEN_AUTH",
    KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO => "KEYGEN_MODES",
    KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO => "KEYOP_MODES",
    KEY_OPERATION_WITH_GENERAL_INFO => "KEYOP_GENERAL",
    KEY_CREATION_PER_UID => "KEYGEN_UID",
    KEY_OPERATION_PER_UID => "KEYOP_UID",
    RKP_ERROR_STATS => "RKP_ERR",
    CRASH_STATS => "CRASH",
    KEYS_PER_UID => "KEYS_PER_UID",
    OPERATION_LATENCY => "OP_LATENCY",
    KEY_OPERATION_STREAMING_STATS => "KEYOP_STREAMING",
);

impl_summary_enum!(MetricsStorage, 28,
    STORAGE_UNSPECIFIED => "UNSPECIFIED",
    KEY_ENTRY => "KEY_ENTRY",
    KEY_ENTRY_ID_INDEX => "KEY_ENTRY_ID_IDX" ,
    KEY_ENTRY_DOMAIN_NAMESPACE_INDEX => "KEY_ENTRY_DOMAIN_NS_IDX" ,
    BLOB_ENTRY => "BLOB_ENTRY",
    BLOB_ENTRY_KEY_ENTRY_ID_INDEX => "BLOB_ENTRY_KEY_ENTRY_ID_IDX" ,
    KEY_PARAMETER => "KEY_PARAMETER",
    KEY_PARAMETER_KEY_ENTRY_ID_INDEX => "KEY_PARAM_KEY_ENTRY_ID_IDX" ,
    KEY_METADATA => "KEY_METADATA",
    KEY_METADATA_KEY_ENTRY_ID_INDEX => "KEY_META_KEY_ENTRY_ID_IDX" ,
    GRANT => "GRANT",
    AUTH_TOKEN => "AUTH_TOKEN",
    BLOB_METADATA => "BLOB_METADATA",
    BLOB_METADATA_BLOB_ENTRY_ID_INDEX => "BLOB_META_BLOB_ENTRY_ID_IDX" ,
    METADATA => "METADATA",
    DATABASE => "DATABASE",
    LEGACY_STORAGE => "LEGACY_STORAGE",
);

impl_summary_enum!(MetricsAlgorithm, 7,
    ALGORITHM_UNSPECIFIED => "NONE",
    RSA => "RSA",
    EC => "EC",
    ML_DSA_65 => "MLDSA65",
    ML_DSA_87 => "MLDSA87",
    AES => "AES",
    TRIPLE_DES => "DES",
    HMAC => "HMAC",
);

impl_summary_enum!(MetricsEcCurve, 5,
    EC_CURVE_UNSPECIFIED => "NONE",
    P_224 => "P-224",
    P_256 => "P-256",
    P_384 => "P-384",
    P_521 => "P-521",
    CURVE_25519 => "25519",
);

impl_summary_enum!(MetricsKeyOrigin, 10,
    ORIGIN_UNSPECIFIED => "UNSPEC",
    GENERATED => "GENERATED",
    DERIVED => "DERIVED",
    IMPORTED => "IMPORTED",
    RESERVED => "RESERVED",
    SECURELY_IMPORTED => "SEC-IMPORT",
);

impl_summary_enum!(MetricsSecurityLevel, 9,
    SECURITY_LEVEL_UNSPECIFIED => "UNSPEC",
    SECURITY_LEVEL_SOFTWARE => "SOFTWARE",
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT => "TEE",
    SECURITY_LEVEL_STRONGBOX => "STRONGBOX",
    SECURITY_LEVEL_KEYSTORE => "KEYSTORE",
);

impl_summary_enum!(MetricsHardwareAuthenticatorType, 8,
    AUTH_TYPE_UNSPECIFIED => "UNSPEC",
    NONE => "NONE",
    PASSWORD => "PASSWD",
    FINGERPRINT => "FPRINT",
    PASSWORD_OR_FINGERPRINT => "PW_OR_FP",
    ANY => "ANY",
    NO_AUTH_TYPE => "NOAUTH",
);

impl_summary_enum!(MetricsPurpose, 7,
    KEY_PURPOSE_UNSPECIFIED => "UNSPEC",
    ENCRYPT => "ENCRYPT",
    DECRYPT => "DECRYPT",
    SIGN => "SIGN",
    VERIFY => "VERIFY",
    WRAP_KEY => "WRAPKEY",
    AGREE_KEY => "AGREEKY",
    ATTEST_KEY => "ATTESTK",
);

impl_summary_enum!(MetricsOutcome, 7,
    OUTCOME_UNSPECIFIED => "UNSPEC",
    DROPPED => "DROPPED",
    SUCCESS => "SUCCESS",
    ABORT => "ABORT",
    PRUNED => "PRUNED",
    ERROR => "ERROR",
);

impl_summary_enum!(MetricsRkpError, 6,
    RKP_ERROR_UNSPECIFIED => "UNSPEC",
    OUT_OF_KEYS => "OOKEYS",
    FALL_BACK_DURING_HYBRID => "FALLBK",
);

impl_summary_enum!(MetricsOperationType, 7,
    UNSPECIFIED => "UNSPEC",
    GENERATE_KEY => "GENKEY",
    IMPORT_KEY => "IMPKEY",
    IMPORT_WRAPPED_KEY => "IMPWKEY",
    CREATE_OPERATION => "BEGIN",
    ENTIRE_OPERATION => "OPERATION",
);

macro_rules! format_clause {
    {  $ignored:ident } => { "{}" }
}

macro_rules! show_enum_bitmask {
    {  $v:expr, $enum:ident, $( $variant:ident => $short:literal ),+ $(,)? } => {
        {
            let v: i32 = $v;
            let mut displayed_mask = 0i32;
            $(
                displayed_mask |= 1 << $enum::$variant as i32;
            )*
            let undisplayed_mask = !displayed_mask;
            let undisplayed = v & undisplayed_mask;
            let extra = if undisplayed == 0 {
                "".to_string()
            } else {
                format!("(full:{v:#010x})")
            };
            format!(
                concat!( $( format_clause!($variant), )* "{}"),
                $(
                    if v & 1 << $enum::$variant as i32 != 0 { $short } else { "-" },
                )*
                extra
            )
        }
    }
}

fn show_purpose(v: i32) -> String {
    show_enum_bitmask!(v, KeyPurposeBitPosition,
        ATTEST_KEY_BIT_POS => "A",
        AGREE_KEY_BIT_POS => "G",
        WRAP_KEY_BIT_POS => "W",
        VERIFY_BIT_POS => "V",
        SIGN_BIT_POS => "S",
        DECRYPT_BIT_POS => "D",
        ENCRYPT_BIT_POS => "E",
    )
}

fn show_padding(v: i32) -> String {
    show_enum_bitmask!(v, PaddingModeBitPosition,
        PKCS7_BIT_POS => "7",
        RSA_PKCS1_1_5_SIGN_BIT_POS => "S",
        RSA_PKCS1_1_5_ENCRYPT_BIT_POS => "E",
        RSA_PSS_BIT_POS => "P",
        RSA_OAEP_BIT_POS => "O",
        NONE_BIT_POSITION => "N",
    )
}

fn show_digest(v: i32) -> String {
    show_enum_bitmask!(v, DigestBitPosition,
        SHA_2_512_BIT_POS => "5",
        SHA_2_384_BIT_POS => "3",
        SHA_2_256_BIT_POS => "2",
        SHA_2_224_BIT_POS => "4",
        SHA_1_BIT_POS => "1",
        MD5_BIT_POS => "M",
        NONE_BIT_POSITION => "N",
    )
}

fn show_blockmode(v: i32) -> String {
    show_enum_bitmask!(v, BlockModeBitPosition,
        GCM_BIT_POS => "G",
        CTR_BIT_POS => "T",
        CBC_BIT_POS => "C",
        ECB_BIT_POS => "E",
    )
}

impl Summary for KeystoreAtomPayload {
    fn show(&self) -> String {
        match self {
            KeystoreAtomPayload::StorageStats(v) => {
                format!(
                    "{} sz={} unused={}",
                    v.storage_type.show(),
                    v.size,
                    v.unused_size
                )
            }
            KeystoreAtomPayload::KeyCreationWithGeneralInfo(v) => {
                format!(
                    "{} ksz={:>4} crv={} {} rc={:4} attest? {}",
                    v.algorithm.show(),
                    v.key_size,
                    v.ec_curve.show(),
                    v.key_origin.show(),
                    v.error_code,
                    if v.attestation_requested { "Y" } else { "N" }
                )
            }
            KeystoreAtomPayload::KeyCreationWithAuthInfo(v) => {
                format!(
                    "auth={} log(time)={:3} sec={}",
                    v.user_auth_type.show(),
                    v.log10_auth_key_timeout_seconds,
                    v.security_level.show()
                )
            }
            KeystoreAtomPayload::KeyCreationWithPurposeAndModesInfo(v) => {
                format!(
                    "{} purpose={} padding={} digest={} blockmode={}",
                    v.algorithm.show(),
                    show_purpose(v.purpose_bitmap),
                    show_padding(v.padding_mode_bitmap),
                    show_digest(v.digest_bitmap),
                    show_blockmode(v.block_mode_bitmap),
                )
            }
            KeystoreAtomPayload::KeyOperationWithGeneralInfo(v) => {
                format!(
                    "{} {:>8} upgraded? {} sec={}",
                    v.outcome.show(),
                    v.error_code,
                    if v.key_upgraded { "Y" } else { "N" },
                    v.security_level.show()
                )
            }
            KeystoreAtomPayload::KeyOperationWithPurposeAndModesInfo(v) => {
                format!(
                    "{} padding={} digest={} blockmode={}",
                    v.purpose.show(),
                    show_padding(v.padding_mode_bitmap),
                    show_digest(v.digest_bitmap),
                    show_blockmode(v.block_mode_bitmap)
                )
            }
            KeystoreAtomPayload::RkpErrorStats(v) => {
                format!("{} sec={}", v.rkpError.show(), v.security_level.show())
            }
            KeystoreAtomPayload::CrashStats(v) => {
                format!("count={}", v.count_of_crash_events)
            }
            KeystoreAtomPayload::Keystore2AtomWithOverflow(v) => {
                format!("atom={}", v.atom_id.show())
            }
            KeystoreAtomPayload::KeysPerUid(v) => {
                format!("uid={} key_count={}", v.uid, v.key_count)
            }
            KeystoreAtomPayload::KeyCreationPerUid(v) => {
                format!(
                    "uid={} sec={} alg={} auth={} attest? {}",
                    v.uid,
                    v.security_level.show(),
                    v.algorithm.show(),
                    v.user_auth_type.show(),
                    if v.attestation_requested { "Y" } else { "N" }
                )
            }
            KeystoreAtomPayload::KeyOperationPerUid(v) => {
                format!("uid={} sec={}", v.uid, v.security_level.show())
            }
            KeystoreAtomPayload::OperationLatency(v) => {
                format!(
                    "op_type={} alg={} size={} crv={} sec={} success? {} latency={}",
                    v.operation_type.show(),
                    v.algorithm.show(),
                    v.key_size,
                    v.ec_curve.show(),
                    v.security_level.show(),
                    if v.is_success { "Y" } else { "N" },
                    v.latency_ms
                )
            }
            KeystoreAtomPayload::KeyOperationStreamingStats(v) => {
                format!(
                    "alg={} success={} call_cnt={} bytes={}",
                    v.algorithm.show(),
                    v.is_success,
                    v.call_count,
                    v.total_input_bytes
                )
            }
        }
    }
}
