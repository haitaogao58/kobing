// Copyright 2020, The Android Open Source Project
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

use crate::android::content::pm::IPackageManagerNative::{IPackageManagerNative, LOCATION_SYSTEM};
use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, Certificate::Certificate, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
    KeyCharacteristics::KeyCharacteristics, KeyCreationResult::KeyCreationResult,
    KeyParameter::KeyParameter as KmKeyParameter, KeyParameterValue::KeyParameterValue,
    MlDsaVariant::MlDsaVariant as AidlMlDsaVariant, SecurityLevel::SecurityLevel, Tag::Tag,
};
use crate::android::system::keystore2::{
    Authorization::Authorization, Domain::Domain, KeyDescriptor::KeyDescriptor,
    ResponseCode::ResponseCode,
};
use crate::err as ks_err;
use crate::keymaster::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, ZVec};
use crate::keymaster::error::{map_km_error, map_ks_error, Error, ErrorCode};
use crate::keymaster::key_parameter::KeyParameter;
use crate::keymaster::permission;
use crate::keymaster::permission::{KeyPerm, KeyPermSet, KeystorePerm};
use crate::keymaster::sw_keyblob;
use crate::plat::utils as user_utils;
pub use crate::watchdog;
use crate::{
    consts,
    keymaster::{
        db::{KeyType, KeystoreDB},
        keymint_device::KeyMintDevice,
    },
};
use anyhow::{anyhow, Context, Result};
use kmr_common::consts::{
    AID_KEYSTORE as RAW_AID_KEYSTORE, AID_ROOT, AID_SYSTEM as RAW_AID_SYSTEM,
};
use kmr_wire::keymint::{self, KeyParam};
use kmr_wire::{KeySizeInBits, ValueNotRecognized};
use log::{debug, error, info, warn};
use rsbinder::{
    get_calling_uid, hub, FromIBinder, ProcessState, SIBinder, Status, StatusCode, Strong,
};
use std::iter::IntoIterator;
use std::thread::sleep;
use std::time::Duration;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AndroidUserId(pub i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppUid(pub i64);

impl AppUid {
    pub fn owning_user(&self) -> AndroidUserId {
        AndroidUserId(user_utils::multiuser_get_user_id(self.0 as u32) as i32)
    }

    pub fn calling() -> Self {
        Self(get_calling_uid() as i64)
    }
}

pub const AID_SYSTEM: AppUid = AppUid(RAW_AID_SYSTEM as i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecureUserId(pub i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Challenge(pub i64);

pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;

pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
    permission::check_keystore_permission(perm, None)
}

pub fn check_grant_permission(access_vec: KeyPermSet, key: &KeyDescriptor) -> anyhow::Result<()> {
    permission::check_grant_permission(access_vec, key, None)
}

pub fn check_key_permission(
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    permission::check_key_permission(perm, key, access_vector.as_ref(), None)
}

pub fn is_device_id_attestation_tag(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::ATTESTATION_ID_IMEI
            | Tag::ATTESTATION_ID_MEID
            | Tag::ATTESTATION_ID_SERIAL
            | Tag::DEVICE_UNIQUE_ATTESTATION
            | Tag::ATTESTATION_ID_SECOND_IMEI
    )
}

pub fn is_imei_attestation_tag(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::ATTESTATION_ID_IMEI | Tag::ATTESTATION_ID_SECOND_IMEI
    )
}

pub fn check_device_attestation_permissions() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.READ_PRIVILEGED_PHONE_STATE",
        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

pub fn check_unique_id_attestation_permissions() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.REQUEST_UNIQUE_ID_ATTESTATION",
        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

pub fn check_get_app_uids_affected_by_sid_permissions() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.MANAGE_USERS",
        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

pub fn check_dump_permission() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.DUMP",
        Error::Rc(ResponseCode::PERMISSION_DENIED),
    )
}

fn check_android_permission(permission: &str, err: Error) -> anyhow::Result<()> {
    let app_id = user_utils::multiuser_get_app_id(AppUid::calling().0 as u32);
    match app_id {
        AID_ROOT | RAW_AID_SYSTEM | RAW_AID_KEYSTORE => Ok(()),
        _ => Err(err).context(ks_err!(
            "caller does not have the '{permission}' permission"
        )),
    }
}

pub fn key_characteristics_to_internal(
    key_characteristics: Vec<KeyCharacteristics>,
) -> Vec<KeyParameter> {
    key_characteristics
        .into_iter()
        .flat_map(|aidl_key_char| {
            let sec_level = aidl_key_char.securityLevel;
            aidl_key_char
                .authorizations
                .into_iter()
                .map(move |aidl_kp| KeyParameter::new(aidl_kp.into(), sec_level))
        })
        .collect()
}

fn import_keyblob_and_perform_op<T, KmOp, NewBlobHandler>(
    km_dev: &dyn IKeyMintDevice,
    inner_keyblob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    let (format, key_material, mut chars) = sw_keyblob::export_key(inner_keyblob, upgrade_params)?;
    debug!(
        "importing {format:?} key material (len={}) with original chars={chars:?}",
        key_material.len(),
    );
    let asymmetric = chars.iter().any(|kp| {
        kp.tag == Tag::ALGORITHM
            && (kp.value == KeyParameterValue::Algorithm(Algorithm::RSA)
                || (kp.value == KeyParameterValue::Algorithm(Algorithm::EC)))
    });

    chars.extend_from_slice(upgrade_params);

    let mut import_params: Vec<KmKeyParameter> = chars
        .into_iter()
        .filter(|kp| {
            !matches!(
                kp.tag,
                Tag::ORIGIN
                    | Tag::ROOT_OF_TRUST
                    | Tag::OS_VERSION
                    | Tag::OS_PATCHLEVEL
                    | Tag::UNIQUE_ID
                    | Tag::ATTESTATION_CHALLENGE
                    | Tag::ATTESTATION_APPLICATION_ID
                    | Tag::ATTESTATION_ID_BRAND
                    | Tag::ATTESTATION_ID_DEVICE
                    | Tag::ATTESTATION_ID_PRODUCT
                    | Tag::ATTESTATION_ID_SERIAL
                    | Tag::ATTESTATION_ID_IMEI
                    | Tag::ATTESTATION_ID_MEID
                    | Tag::ATTESTATION_ID_MANUFACTURER
                    | Tag::ATTESTATION_ID_MODEL
                    | Tag::VENDOR_PATCHLEVEL
                    | Tag::BOOT_PATCHLEVEL
                    | Tag::DEVICE_UNIQUE_ATTESTATION
                    | Tag::ATTESTATION_ID_SECOND_IMEI
                    | Tag::NONCE
                    | Tag::MAC_LENGTH
                    | Tag::CERTIFICATE_SERIAL
                    | Tag::CERTIFICATE_SUBJECT
                    | Tag::CERTIFICATE_NOT_BEFORE
                    | Tag::CERTIFICATE_NOT_AFTER
            )
        })
        .collect();

    if asymmetric {
        import_params.push(KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_BEFORE,
            value: KeyParameterValue::DateTime(0),
        });
        import_params.push(KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_AFTER,
            value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
        });
    }
    debug!("import parameters={import_params:?}");

    let creation_result = {
        let _wp = watchdog::watch(
            "utils::import_keyblob_and_perform_op: calling IKeyMintDevice::importKey",
        );
        map_km_error(km_dev.importKey(&import_params, format, &key_material, None))
    }
    .context(ks_err!("Upgrade failed."))?;

    new_blob_handler(&creation_result.keyBlob).context(ks_err!("calling new_blob_handler."))?;

    km_op(&creation_result.keyBlob)
        .map(|v| (v, Some(creation_result.keyBlob)))
        .context(ks_err!("Calling km_op after upgrade."))
}

fn upgrade_keyblob_and_perform_op<T, KmOp, NewBlobHandler>(
    km_dev: &dyn IKeyMintDevice,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    let upgraded_blob = {
        let _wp = watchdog::watch(
            "utils::upgrade_keyblob_and_perform_op: calling IKeyMintDevice::upgradeKey.",
        );
        map_km_error(km_dev.upgradeKey(key_blob, upgrade_params))
    }
    .context(ks_err!("Upgrade failed."))?;

    new_blob_handler(&upgraded_blob).context(ks_err!("calling new_blob_handler."))?;

    km_op(&upgraded_blob)
        .map(|v| (v, Some(upgraded_blob)))
        .context(ks_err!("Calling km_op after upgrade."))
}

pub fn upgrade_keyblob_if_required_with<T, KmOp, NewBlobHandler>(
    km_dev: &dyn IKeyMintDevice,
    km_dev_version: i32,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    match km_op(key_blob) {
        Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => upgrade_keyblob_and_perform_op(
            km_dev,
            key_blob,
            upgrade_params,
            km_op,
            new_blob_handler,
        ),
        Err(Error::Km(ErrorCode::INVALID_KEY_BLOB))
            if km_dev_version >= KeyMintDevice::KEY_MINT_V1 =>
        {
            if key_blob.starts_with(consts::KEYMASTER_BLOB_HW_PREFIX) {
                info!("found apparent km_compat(Keymaster) HW blob, attempt strip-and-upgrade");
                let inner_keyblob = &key_blob[consts::KEYMASTER_BLOB_HW_PREFIX.len()..];
                upgrade_keyblob_and_perform_op(
                    km_dev,
                    inner_keyblob,
                    upgrade_params,
                    km_op,
                    new_blob_handler,
                )
            } else if crate::keymaster::flags::import_previously_emulated_keys()
                && key_blob.starts_with(consts::KEYMASTER_BLOB_SW_PREFIX)
            {
                info!("found apparent km_compat(Keymaster) SW blob, attempt strip-and-import");
                let inner_keyblob = &key_blob[consts::KEYMASTER_BLOB_SW_PREFIX.len()..];
                import_keyblob_and_perform_op(
                    km_dev,
                    inner_keyblob,
                    upgrade_params,
                    km_op,
                    new_blob_handler,
                )
            } else {
                Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(ks_err!("Calling km_op"))
            }
        }
        r => r.map(|v| (v, None)).context(ks_err!("Calling km_op.")),
    }
}

pub fn key_parameters_to_authorizations(parameters: Vec<KeyParameter>) -> Vec<Authorization> {
    parameters
        .into_iter()
        .map(|p| p.into_authorization())
        .collect()
}

macro_rules! check_bool {
    {
        $val:expr
    } => {
        if let KeyParameterValue::BoolValue(true) = $val {
            Ok(())
        } else {
            Err(ValueNotRecognized::Bool)
        }
    }
}

pub fn key_parameter_conversion_error_code(error: ValueNotRecognized) -> ErrorCode {
    match error {
        ValueNotRecognized::KeyPurpose => ErrorCode::UNSUPPORTED_PURPOSE,
        ValueNotRecognized::Algorithm => ErrorCode::UNSUPPORTED_ALGORITHM,
        ValueNotRecognized::BlockMode => ErrorCode::UNSUPPORTED_BLOCK_MODE,
        ValueNotRecognized::PaddingMode => ErrorCode::UNSUPPORTED_PADDING_MODE,
        ValueNotRecognized::Digest => ErrorCode::UNSUPPORTED_DIGEST,
        ValueNotRecognized::KeyFormat => ErrorCode::UNSUPPORTED_KEY_FORMAT,
        ValueNotRecognized::EcCurve => ErrorCode::UNSUPPORTED_EC_CURVE,
        ValueNotRecognized::MlDsaVariant => {
            ErrorCode(kmr_wire::keymint::ErrorCode::UnsupportedMlDsaVariant as i32)
        }
        _ => ErrorCode::INVALID_ARGUMENT,
    }
}

impl HardwareAuthToken {
    pub fn to_km(&self) -> Result<kmr_wire::keymint::HardwareAuthToken, Error> {
        Ok(kmr_wire::keymint::HardwareAuthToken {
            challenge: self.challenge,
            user_id: self.userId,
            authenticator_id: self.authenticatorId,
            authenticator_type: kmr_wire::keymint::HardwareAuthenticatorType::try_from(
                self.authenticatorType.0,
            )
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))?,
            timestamp: kmr_wire::secureclock::Timestamp {
                milliseconds: self.timestamp.milliSeconds,
            },
            mac: self.mac.clone(),
        })
    }
}

impl KmKeyParameter {
    pub fn to_km(self) -> Result<KeyParam> {
        self.to_km_optional(KeyMintDevice::KEY_MINT_V5)
            .map_err(|error| anyhow!("Failed to convert key parameter: {error:?}"))?
            .ok_or_else(|| anyhow!(ks_err!("Invalid tag")))
    }

    pub fn to_km_optional(
        self,
        km_dev_version: i32,
    ) -> std::result::Result<Option<KeyParam>, ValueNotRecognized> {
        let tag = match keymint::Tag::try_from(self.tag.0) {
            Ok(tag) => tag,
            Err(_) => return Ok(None),
        };
        let value = self.value;

        Ok(match tag {
            keymint::Tag::Invalid => None,
            keymint::Tag::Purpose => match value {
                KeyParameterValue::KeyPurpose(v) => Some(KeyParam::Purpose(
                    kmr_wire::keymint::KeyPurpose::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::KeyPurpose),
            },
            keymint::Tag::Algorithm => match value {
                KeyParameterValue::Algorithm(v) => {
                    let algorithm = kmr_wire::keymint::Algorithm::try_from(v.0)?;
                    if km_dev_version < KeyMintDevice::KEY_MINT_V5
                        && algorithm == kmr_wire::keymint::Algorithm::MlDsa
                    {
                        return Err(ValueNotRecognized::Algorithm);
                    }
                    Some(KeyParam::Algorithm(algorithm))
                }
                _ => return Err(ValueNotRecognized::Algorithm),
            },
            keymint::Tag::KeySize => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::KeySize(KeySizeInBits(v as u32))),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::BlockMode => match value {
                KeyParameterValue::BlockMode(v) => Some(KeyParam::BlockMode(
                    kmr_wire::keymint::BlockMode::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::BlockMode),
            },
            keymint::Tag::Digest => match value {
                KeyParameterValue::Digest(v) => {
                    Some(KeyParam::Digest(kmr_wire::keymint::Digest::try_from(v.0)?))
                }
                _ => return Err(ValueNotRecognized::Digest),
            },
            keymint::Tag::Padding => match value {
                KeyParameterValue::PaddingMode(v) => Some(KeyParam::Padding(
                    kmr_wire::keymint::PaddingMode::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::PaddingMode),
            },
            keymint::Tag::CallerNonce => {
                check_bool!(value)?;
                Some(KeyParam::CallerNonce)
            }
            keymint::Tag::MinMacLength => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MinMacLength(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::EcCurve => match value {
                KeyParameterValue::EcCurve(v) => {
                    let curve = kmr_wire::keymint::EcCurve::try_from(v.0)?;
                    if km_dev_version < KeyMintDevice::KEY_MINT_V2
                        && curve == kmr_wire::keymint::EcCurve::Curve25519
                    {
                        return Err(ValueNotRecognized::EcCurve);
                    }
                    Some(KeyParam::EcCurve(curve))
                }
                _ => return Err(ValueNotRecognized::EcCurve),
            },
            keymint::Tag::MlDsaVariant if km_dev_version < KeyMintDevice::KEY_MINT_V5 => None,
            keymint::Tag::MlDsaVariant => match value {
                KeyParameterValue::MlDsaVariant(v) => Some(KeyParam::MlDsaVariant(
                    kmr_wire::keymint::MlDsaVariant::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::MlDsaVariant),
            },
            keymint::Tag::RsaPublicExponent => match value {
                KeyParameterValue::LongInteger(v) => {
                    Some(KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(v as u64)))
                }
                _ => return Err(ValueNotRecognized::LongInteger),
            },
            keymint::Tag::IncludeUniqueId => {
                check_bool!(value)?;
                Some(KeyParam::IncludeUniqueId)
            }
            keymint::Tag::RsaOaepMgfDigest => match value {
                KeyParameterValue::Digest(v) => Some(KeyParam::RsaOaepMgfDigest(
                    kmr_wire::keymint::Digest::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::Digest),
            },
            keymint::Tag::BootloaderOnly => {
                check_bool!(value)?;
                Some(KeyParam::BootloaderOnly)
            }
            keymint::Tag::RollbackResistance => {
                check_bool!(value)?;
                Some(KeyParam::RollbackResistance)
            }
            keymint::Tag::HardwareType => return Err(ValueNotRecognized::Tag),
            keymint::Tag::EarlyBootOnly => {
                check_bool!(value)?;
                Some(KeyParam::EarlyBootOnly)
            }
            keymint::Tag::ActiveDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::ActiveDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::OriginationExpireDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::OriginationExpireDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::UsageExpireDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::UsageExpireDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::MinSecondsBetweenOps => return Err(ValueNotRecognized::Tag),
            keymint::Tag::MaxUsesPerBoot => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MaxUsesPerBoot(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UsageCountLimit => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::UsageCountLimit(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UserId => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::UserId(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UserSecureId => match value {
                KeyParameterValue::LongInteger(v) => Some(KeyParam::UserSecureId(v as u64)),
                _ => return Err(ValueNotRecognized::LongInteger),
            },
            keymint::Tag::NoAuthRequired => {
                check_bool!(value)?;
                Some(KeyParam::NoAuthRequired)
            }
            keymint::Tag::UserAuthType => match value {
                KeyParameterValue::HardwareAuthenticatorType(v) => {
                    Some(KeyParam::UserAuthType(v.0 as u32))
                }
                _ => return Err(ValueNotRecognized::HardwareAuthenticatorType),
            },
            keymint::Tag::AuthTimeout => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::AuthTimeout(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::AllowWhileOnBody => {
                check_bool!(value)?;
                Some(KeyParam::AllowWhileOnBody)
            }
            keymint::Tag::TrustedUserPresenceRequired => {
                check_bool!(value)?;
                Some(KeyParam::TrustedUserPresenceRequired)
            }
            keymint::Tag::TrustedConfirmationRequired => {
                check_bool!(value)?;
                Some(KeyParam::TrustedConfirmationRequired)
            }
            keymint::Tag::UnlockedDeviceRequired => {
                check_bool!(value)?;
                Some(KeyParam::UnlockedDeviceRequired)
            }
            keymint::Tag::ApplicationId => match value {
                KeyParameterValue::Blob(v) => Some(KeyParam::ApplicationId(v)),
                _ => return Err(ValueNotRecognized::Blob),
            },
            keymint::Tag::ApplicationData => match value {
                KeyParameterValue::Blob(v) => Some(KeyParam::ApplicationData(v)),
                _ => return Err(ValueNotRecognized::Blob),
            },
            keymint::Tag::CreationDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::CreationDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::Origin => match value {
                KeyParameterValue::Origin(v) => Some(KeyParam::Origin(
                    kmr_wire::keymint::KeyOrigin::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::KeyOrigin),
            },
            keymint::Tag::RootOfTrust => match value {
                KeyParameterValue::Blob(v) => Some(KeyParam::RootOfTrust(v)),
                _ => return Err(ValueNotRecognized::Blob),
            },
            keymint::Tag::OsVersion => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::OsVersion(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::OsPatchlevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::OsPatchlevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UniqueId => return Err(ValueNotRecognized::Tag),
            keymint::Tag::AttestationChallenge => {
                blob_param(value, KeyParam::AttestationChallenge)?
            }
            keymint::Tag::AttestationApplicationId => {
                blob_param(value, KeyParam::AttestationApplicationId)?
            }
            keymint::Tag::AttestationIdBrand => blob_param(value, KeyParam::AttestationIdBrand)?,
            keymint::Tag::AttestationIdDevice => blob_param(value, KeyParam::AttestationIdDevice)?,
            keymint::Tag::AttestationIdProduct => {
                blob_param(value, KeyParam::AttestationIdProduct)?
            }
            keymint::Tag::AttestationIdSerial => blob_param(value, KeyParam::AttestationIdSerial)?,
            keymint::Tag::AttestationIdImei => blob_param(value, KeyParam::AttestationIdImei)?,
            keymint::Tag::AttestationIdMeid => blob_param(value, KeyParam::AttestationIdMeid)?,
            keymint::Tag::AttestationIdManufacturer => {
                blob_param(value, KeyParam::AttestationIdManufacturer)?
            }
            keymint::Tag::AttestationIdModel => blob_param(value, KeyParam::AttestationIdModel)?,
            keymint::Tag::VendorPatchlevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::VendorPatchlevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::BootPatchlevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::BootPatchlevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::DeviceUniqueAttestation => {
                check_bool!(value)?;
                Some(KeyParam::DeviceUniqueAttestation)
            }
            keymint::Tag::IdentityCredentialKey => return Err(ValueNotRecognized::Tag),
            keymint::Tag::StorageKey => {
                check_bool!(value)?;
                Some(KeyParam::StorageKey)
            }
            keymint::Tag::AttestationIdSecondImei
                if km_dev_version < KeyMintDevice::KEY_MINT_V3 =>
            {
                None
            }
            keymint::Tag::AttestationIdSecondImei => {
                blob_param(value, KeyParam::AttestationIdSecondImei)?
            }
            keymint::Tag::AssociatedData => return Err(ValueNotRecognized::Tag),
            keymint::Tag::Nonce => blob_param(value, KeyParam::Nonce)?,
            keymint::Tag::MacLength => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MacLength(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::ResetSinceIdRotation => {
                check_bool!(value)?;
                Some(KeyParam::ResetSinceIdRotation)
            }
            keymint::Tag::ConfirmationToken => return Err(ValueNotRecognized::Tag),
            keymint::Tag::CertificateSerial => blob_param(value, KeyParam::CertificateSerial)?,
            keymint::Tag::CertificateSubject => blob_param(value, KeyParam::CertificateSubject)?,
            keymint::Tag::CertificateNotBefore => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::CertificateNotBefore(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::CertificateNotAfter => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::CertificateNotAfter(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::MaxBootLevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MaxBootLevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::ModuleHash if km_dev_version < KeyMintDevice::KEY_MINT_V4 => None,
            keymint::Tag::ModuleHash => blob_param(value, KeyParam::ModuleHash)?,
        })
    }
}

pub fn key_parameters_to_km(
    parameters: &[KmKeyParameter],
    km_dev_version: i32,
) -> std::result::Result<Vec<KeyParam>, ValueNotRecognized> {
    parameters
        .iter()
        .cloned()
        .try_fold(Vec::new(), |mut result, param| {
            if let Some(param) = param.to_km_optional(km_dev_version)? {
                result.push(param);
            }
            Ok(result)
        })
}

fn blob_param(
    value: KeyParameterValue,
    f: impl FnOnce(Vec<u8>) -> KeyParam,
) -> std::result::Result<Option<KeyParam>, ValueNotRecognized> {
    match value {
        KeyParameterValue::Blob(v) => Ok(Some(f(v))),
        _ => Err(ValueNotRecognized::Blob),
    }
}

pub fn key_creation_result_to_aidl(
    result: kmr_wire::keymint::KeyCreationResult,
    km_dev_version: i32,
) -> Result<KeyCreationResult, rsbinder::Status> {
    let certificates: Vec<Certificate> = result
        .certificate_chain
        .iter()
        .map(|c| Certificate {
            encodedCertificate: c.encoded_certificate.clone(),
        })
        .collect();

    let key_characteristics: Result<Vec<KeyCharacteristics>, rsbinder::Status> = result
        .key_characteristics
        .iter()
        .map(|kc| {
            let params = key_params_to_aidl(&kc.authorizations, km_dev_version)
                .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                .map_err(map_ks_error)?;

            Ok(KeyCharacteristics {
                authorizations: params,
                securityLevel: SecurityLevel(kc.security_level as i32),
            })
        })
        .collect();

    Ok(KeyCreationResult {
        keyBlob: result.key_blob,
        keyCharacteristics: key_characteristics?,
        certificateChain: certificates,
    })
}

pub fn key_params_to_aidl(params: &[KeyParam], km_dev_version: i32) -> Result<Vec<KmKeyParameter>> {
    params
        .iter()
        .cloned()
        .map(|param| key_param_to_aidl(param, km_dev_version))
        .collect()
}

pub fn key_param_to_aidl(kp: KeyParam, km_dev_version: i32) -> Result<KmKeyParameter> {
    let mut tag = Tag(kp.tag() as i32);
    let value = match kp {
        KeyParam::Purpose(v) => KeyParameterValue::KeyPurpose(
            crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose(v as i32),
        ),
        KeyParam::Algorithm(v) => KeyParameterValue::Algorithm(Algorithm(v as i32)),
        KeyParam::KeySize(KeySizeInBits(v)) => KeyParameterValue::Integer(v as i32),
        KeyParam::BlockMode(v) => KeyParameterValue::BlockMode(
            crate::android::hardware::security::keymint::BlockMode::BlockMode(v as i32),
        ),
        KeyParam::Digest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KeyParam::Padding(v) => KeyParameterValue::PaddingMode(
            crate::android::hardware::security::keymint::PaddingMode::PaddingMode(v as i32),
        ),
        KeyParam::CallerNonce => KeyParameterValue::BoolValue(true),
        KeyParam::MinMacLength(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::EcCurve(v) => KeyParameterValue::EcCurve(
            crate::android::hardware::security::keymint::EcCurve::EcCurve(v as i32),
        ),
        KeyParam::MlDsaVariant(v) if km_dev_version < KeyMintDevice::KEY_MINT_V5 => {
            error!("TA emitted ML_DSA_VARIANT tag but HAL v5 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Integer(v as i32)
        }
        KeyParam::MlDsaVariant(v) => KeyParameterValue::MlDsaVariant(AidlMlDsaVariant(v as i32)),
        KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(v)) => {
            KeyParameterValue::LongInteger(v as i64)
        }
        KeyParam::IncludeUniqueId => KeyParameterValue::BoolValue(true),
        KeyParam::RsaOaepMgfDigest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KeyParam::BootloaderOnly
        | KeyParam::RollbackResistance
        | KeyParam::EarlyBootOnly
        | KeyParam::NoAuthRequired
        | KeyParam::AllowWhileOnBody
        | KeyParam::TrustedUserPresenceRequired
        | KeyParam::TrustedConfirmationRequired
        | KeyParam::UnlockedDeviceRequired
        | KeyParam::DeviceUniqueAttestation
        | KeyParam::StorageKey
        | KeyParam::ResetSinceIdRotation => KeyParameterValue::BoolValue(true),
        KeyParam::ActiveDatetime(v)
        | KeyParam::OriginationExpireDatetime(v)
        | KeyParam::UsageExpireDatetime(v)
        | KeyParam::CreationDatetime(v)
        | KeyParam::CertificateNotBefore(v)
        | KeyParam::CertificateNotAfter(v) => KeyParameterValue::DateTime(v.ms_since_epoch),
        KeyParam::MaxUsesPerBoot(v)
        | KeyParam::UsageCountLimit(v)
        | KeyParam::UserId(v)
        | KeyParam::AuthTimeout(v)
        | KeyParam::OsVersion(v)
        | KeyParam::OsPatchlevel(v)
        | KeyParam::VendorPatchlevel(v)
        | KeyParam::BootPatchlevel(v)
        | KeyParam::MacLength(v)
        | KeyParam::MaxBootLevel(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::UserAuthType(v) => {
            KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType(v as i32))
        }
        KeyParam::UserSecureId(v) => KeyParameterValue::LongInteger(v as i64),
        KeyParam::ApplicationId(v)
        | KeyParam::ApplicationData(v)
        | KeyParam::RootOfTrust(v)
        | KeyParam::AttestationChallenge(v)
        | KeyParam::AttestationApplicationId(v)
        | KeyParam::AttestationIdBrand(v)
        | KeyParam::AttestationIdDevice(v)
        | KeyParam::AttestationIdProduct(v)
        | KeyParam::AttestationIdSerial(v)
        | KeyParam::AttestationIdImei(v)
        | KeyParam::AttestationIdMeid(v)
        | KeyParam::AttestationIdManufacturer(v)
        | KeyParam::AttestationIdModel(v)
        | KeyParam::Nonce(v)
        | KeyParam::CertificateSerial(v)
        | KeyParam::CertificateSubject(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdSecondImei(v) if km_dev_version < KeyMintDevice::KEY_MINT_V3 => {
            error!("TA emitted ATTESTATION_ID_SECOND_IMEI tag but HAL v3 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Blob(v)
        }
        KeyParam::AttestationIdSecondImei(v) => KeyParameterValue::Blob(v),
        KeyParam::ModuleHash(v) if km_dev_version < KeyMintDevice::KEY_MINT_V4 => {
            error!("TA emitted MODULE_HASH tag but HAL v4 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Blob(v)
        }
        KeyParam::ModuleHash(v) => KeyParameterValue::Blob(v),
        KeyParam::Origin(v) => KeyParameterValue::Origin(
            crate::android::hardware::security::keymint::KeyOrigin::KeyOrigin(v as i32),
        ),
    };

    Ok(KmKeyParameter { tag, value })
}

#[allow(clippy::unnecessary_cast)]
pub fn get_current_time_in_milliseconds() -> i64 {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current_time) };
    current_time.tv_sec as i64 * 1000 + (current_time.tv_nsec as i64 / 1_000_000)
}

pub const AID_USER_OFFSET: u32 = user_utils::AID_USER_OFFSET;

pub const AID_KEYSTORE: AppUid = AppUid(RAW_AID_KEYSTORE as i64);

#[cfg(test)]
fn merge_and_filter_key_entry_lists(
    legacy_descriptors: &[KeyDescriptor],
    db_descriptors: &[KeyDescriptor],
    start_past_alias: Option<&str>,
) -> Vec<KeyDescriptor> {
    let mut result: Vec<KeyDescriptor> = match start_past_alias {
        Some(past_alias) => legacy_descriptors
            .iter()
            .filter(|kd| {
                if let Some(alias) = &kd.alias {
                    alias.as_str() > past_alias
                } else {
                    false
                }
            })
            .cloned()
            .collect(),
        None => legacy_descriptors.to_vec(),
    };

    result.extend_from_slice(db_descriptors);
    result.sort_unstable();
    result.dedup();
    result
}

pub(crate) fn estimate_safe_amount_to_return(
    domain: Domain,
    namespace: i64,
    start_past_alias: Option<&str>,
    key_descriptors: &[KeyDescriptor],
    response_size_limit: usize,
) -> usize {
    let mut count = 0;
    let mut bytes: usize = 0;

    for kd in key_descriptors.iter() {
        bytes += 4 + 8;

        if let Some(alias) = &kd.alias {
            bytes += 4 + alias.len();
        }

        if let Some(blob) = &kd.blob {
            bytes += 4 + blob.len();
        }

        if bytes > response_size_limit {
            warn!(
                "{domain:?}:{namespace}: Key descriptors list ({} items after {start_past_alias:?}) \
                 may exceed binder size, returning {count} items est. {bytes} bytes",
                key_descriptors.len(),
            );
            break;
        }
        count += 1;
    }
    count
}

pub(crate) const RESPONSE_SIZE_LIMIT: usize = 358400;

pub fn list_key_entries(
    db: &mut KeystoreDB,
    domain: Domain,
    namespace: i64,
    start_past_alias: Option<&str>,
) -> Result<Vec<KeyDescriptor>> {
    let key_descriptors: Vec<KeyDescriptor> = db
        .list_past_alias(domain, namespace, KeyType::Client, start_past_alias)
        .context(ks_err!("Trying to list keystore database past alias."))?;

    let safe_amount_to_return = estimate_safe_amount_to_return(
        domain,
        namespace,
        start_past_alias,
        &key_descriptors,
        RESPONSE_SIZE_LIMIT,
    );
    Ok(key_descriptors[..safe_amount_to_return].to_vec())
}

pub fn count_key_entries(db: &mut KeystoreDB, domain: Domain, namespace: i64) -> Result<i32> {
    Ok(db.count_keys(domain, namespace, KeyType::Client)? as i32)
}

pub fn log_security_safe_params(params: &[KmKeyParameter]) -> Vec<KmKeyParameter> {
    params
        .iter()
        .filter(|kp| kp.tag != Tag::APPLICATION_ID && kp.tag != Tag::APPLICATION_DATA)
        .cloned()
        .collect::<Vec<KmKeyParameter>>()
}

pub trait AesGcm {
    fn decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec>;

    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;
}

pub trait AesGcmKey {
    fn key(&self) -> &[u8];
}

impl<T: AesGcmKey> AesGcm for T {
    fn decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec> {
        aes_gcm_decrypt(data, iv, tag, self.key()).context(ks_err!("Decryption failed"))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        aes_gcm_encrypt(plaintext, self.key()).context(ks_err!("Encryption failed."))
    }
}

pub(crate) fn get_interface_once<T: FromIBinder + ?Sized>(
    name: &str,
) -> Result<Strong<T>, StatusCode> {
    let binder = hub::default()?
        .try_get_service(name)
        .ok()
        .flatten()
        .ok_or(StatusCode::NameNotFound)?;
    FromIBinder::try_from(binder)
}

pub fn retry_get_interface<T: FromIBinder + ?Sized>(
    name: &str,
    retry_count: usize,
) -> Result<Strong<T>, StatusCode> {
    let mut attempts = 0;
    let mut wait_time = Duration::from_secs(1);
    loop {
        let err = match get_interface_once(name) {
            Ok(res) => {
                if attempts > 1 {
                    info!("Success on get_interface({name}) after {attempts} failures!");
                }
                return Ok(res);
            }
            Err(e) => e,
        };
        attempts += 1;
        error!("Failed (attempt {attempts} of {retry_count}) to get_interface {name}: {err:?}");
        if attempts >= retry_count {
            error!("Give up retrying after {attempts} failures, return final error: {err:?}");
            return Err(err);
        }
        info!("Blocking wait {wait_time:?} before retry of get_interface({name})");
        sleep(wait_time);
        wait_time *= 2;
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppInfo {
    pub target_sdk: Option<i32>,

    pub is_system_app: bool,
}

const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageManagerNativeLayout {
    Android12To14,
    Android15Or16,
    Android17,
}

fn package_manager_native_layout(android_major: Option<i32>) -> PackageManagerNativeLayout {
    match android_major {
        Some(version) if version >= 17 => PackageManagerNativeLayout::Android17,
        Some(15 | 16) | None => PackageManagerNativeLayout::Android15Or16,
        _ => PackageManagerNativeLayout::Android12To14,
    }
}

fn legacy_pm_transactions(
    layout: PackageManagerNativeLayout,
) -> (rsbinder::TransactionCode, rsbinder::TransactionCode) {
    match layout {
        PackageManagerNativeLayout::Android12To14 => (
            rsbinder::FIRST_CALL_TRANSACTION + 5,
            rsbinder::FIRST_CALL_TRANSACTION + 4,
        ),
        PackageManagerNativeLayout::Android15Or16 => (
            rsbinder::FIRST_CALL_TRANSACTION + 6,
            rsbinder::FIRST_CALL_TRANSACTION + 5,
        ),
        PackageManagerNativeLayout::Android17 => unreachable!("Android 17 uses generated AIDL"),
    }
}

pub fn app_info_for_uid(uid: AppUid) -> AppInfo {
    let app_id = user_utils::multiuser_get_app_id(uid.0 as u32);
    let app_info = AppInfo {
        target_sdk: None,
        is_system_app: matches!(app_id, AID_ROOT | RAW_AID_SYSTEM | RAW_AID_KEYSTORE),
    };

    if !ProcessState::is_initialized() {
        return app_info;
    }

    let pm: Strong<dyn IPackageManagerNative> =
        match get_interface_once(PACKAGE_MANAGER_NATIVE_SERVICE) {
            Ok(pm) => pm,
            Err(e) => {
                warn!("failed to connect to PackageManager: {e:?}");
                return app_info;
            }
        };

    match package_manager_native_layout(kmr_common::android_version::android_major_version()) {
        layout @ (PackageManagerNativeLayout::Android12To14
        | PackageManagerNativeLayout::Android15Or16) => {
            app_info_for_uid_legacy_pm(&pm, uid, app_info, layout)
        }
        PackageManagerNativeLayout::Android17 => app_info_for_uid_android_17_pm(&pm, uid, app_info),
    }
}

fn app_info_for_uid_android_17_pm(
    pm: &Strong<dyn IPackageManagerNative>,
    uid: AppUid,
    mut app_info: AppInfo,
) -> AppInfo {
    let pkg_infos = match pm.getPackageInfoWithSigningInfoForUid(uid.0 as i32) {
        Ok(Some(infos)) => infos,
        Ok(None) => {
            warn!("no package info for {uid:?}");
            return app_info;
        }
        Err(e) => {
            warn!("failed to get package info for {uid:?}: {e:?}");
            return app_info;
        }
    };

    for pkg_info in pkg_infos.into_iter().flatten() {
        let pkg_name = pkg_info.r#packageName.as_str();
        if pkg_name.is_empty() {
            continue;
        }
        update_app_info_with_target_sdk(
            uid,
            pkg_name,
            pm.getTargetSdkVersionForPackage(pkg_name),
            &mut app_info,
        );
        if !app_info.is_system_app {
            update_app_info_with_location_flags(
                uid,
                pkg_name,
                pm.getLocationFlags(pkg_name),
                &mut app_info,
            );
        }
    }

    app_info
}

fn app_info_for_uid_legacy_pm(
    pm: &Strong<dyn IPackageManagerNative>,
    uid: AppUid,
    mut app_info: AppInfo,
    layout: PackageManagerNativeLayout,
) -> AppInfo {
    let (target_sdk_transaction, location_flags_transaction) = legacy_pm_transactions(layout);
    let pkg_names = match pm.getNamesForUids(&[uid.0 as i32]) {
        Ok(names) => names,
        Err(e) => {
            warn!("failed to get package names for {uid:?}: {e:?}");
            return app_info;
        }
    };

    let binder = match hub::try_get_service(PACKAGE_MANAGER_NATIVE_SERVICE)
        .ok()
        .flatten()
    {
        Some(binder) => binder,
        None => {
            warn!("failed to connect to PackageManager service binder");
            return app_info;
        }
    };

    for pkg_name in pkg_names.iter().filter(|name| !name.is_empty()) {
        let pkg_name = pkg_name.as_str();
        update_app_info_with_target_sdk(
            uid,
            pkg_name,
            package_manager_native_get_i32_for_package(
                &binder,
                target_sdk_transaction,
                pkg_name,
                "target SDK version",
            ),
            &mut app_info,
        );
        if !app_info.is_system_app {
            update_app_info_with_location_flags(
                uid,
                pkg_name,
                package_manager_native_get_i32_for_package(
                    &binder,
                    location_flags_transaction,
                    pkg_name,
                    "location flags",
                ),
                &mut app_info,
            );
        }
    }

    app_info
}
fn update_app_info_with_target_sdk<E: std::fmt::Debug>(
    uid: AppUid,
    pkg_name: &str,
    target_sdk: std::result::Result<i32, E>,
    app_info: &mut AppInfo,
) {
    match target_sdk {
        Err(e) => warn!("failed to get target SDK version for {uid:?} '{pkg_name}': {e:?}"),
        Ok(target_sdk) if target_sdk <= 0 => {
            warn!("unexpected target SDK version {target_sdk} for {uid:?} '{pkg_name}'");
        }
        Ok(target_sdk) => match app_info.target_sdk {
            Some(prev_lowest) if target_sdk < prev_lowest => {
                app_info.target_sdk = Some(target_sdk);
            }
            None => app_info.target_sdk = Some(target_sdk),
            _ => {}
        },
    }
}

fn update_app_info_with_location_flags<E: std::fmt::Debug>(
    uid: AppUid,
    pkg_name: &str,
    location_flags: std::result::Result<i32, E>,
    app_info: &mut AppInfo,
) {
    match location_flags {
        Err(e) => warn!("failed to get location flags for {uid:?} '{pkg_name}': {e:?}"),
        Ok(flags) if flags & LOCATION_SYSTEM != 0 => app_info.is_system_app = true,
        Ok(_) => {}
    }
}

fn package_manager_native_get_i32_for_package(
    binder: &SIBinder,
    transaction: rsbinder::TransactionCode,
    package_name: &str,
    label: &str,
) -> Result<i32> {
    let proxy = binder
        .as_proxy()
        .context("PackageManager binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare PackageManager transaction")?;
    data.write(package_name)
        .with_context(|| format!("failed to write PackageManager {label} package name"))?;

    let mut reply = proxy
        .submit_transact(transaction, &data, rsbinder::FLAG_CLEAR_BUF)
        .with_context(|| format!("PackageManager {label} transact failed"))?
        .with_context(|| format!("PackageManager {label} returned no reply"))?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .with_context(|| format!("failed to decode PackageManager {label} status"))?;
    if !status.is_ok() {
        return Err(anyhow::Error::new(status))
            .with_context(|| format!("PackageManager {label} returned non-ok status"));
    }

    reply
        .read()
        .with_context(|| format!("failed to decode PackageManager {label} result"))
}

fn errno_clear() {
    unsafe { *libc::__errno() = 0 }
}

fn errno_read() -> libc::c_int {
    unsafe { *libc::__errno() }
}

fn getpriority() -> Option<libc::c_int> {
    errno_clear();

    let result = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };

    let errno = errno_read();
    if errno == 0 {
        Some(result)
    } else {
        warn!("getpriority() failed (errno={errno})");
        None
    }
}

fn setpriority(prio: libc::c_int) {
    errno_clear();

    let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, prio) };
    if result != 0 {
        let errno = errno_read();
        warn!("setpriority() failed (errno={errno})");
    }
}

pub fn self_renice(niceness: i32) {
    let Some(current) = getpriority() else { return };
    if current > niceness {
        info!("setting niceness {niceness} from current {current}");
        setpriority(niceness)
    }
}

#[cfg(test)]
pub fn init_test_logging() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_test")
            .with_max_level(log::LevelFilter::Debug),
    );
}

#[cfg(test)]
pub fn init_test_logging_at(max_level: log::LevelFilter) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_test")
            .with_max_level(max_level),
    );
}
