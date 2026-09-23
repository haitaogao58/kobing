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
    contains_tag_value, crypto, crypto::aes, km_err, tag, try_to_vec, vec_try, Error,
    FallibleAllocExt,
};
use kmr_derive::AsCborValue;
use kmr_wire::keymint::{
    BootInfo, KeyCharacteristics, KeyParam, KeyPurpose, SecurityLevel, VerifiedBootState,
};
use kmr_wire::{cbor, cbor_type_error, AsCborValue, CborError};
use log::{error, info};
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use zeroize::ZeroizeOnDrop;

pub mod legacy;
pub mod sdd_mem;

#[cfg(test)]
mod tests;

const ZERO_NONCE: [u8; 12] = [0u8; 12];

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, AsCborValue)]
pub struct SecureDeletionSlot(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, AsCborValue)]
pub enum Version {
    V1 = 0,
}

#[derive(Clone, Debug)]
pub enum EncryptedKeyBlob {
    V1(EncryptedKeyBlobV1),
}

impl EncryptedKeyBlob {
    pub fn new(data: &[u8]) -> Result<Self, Error> {
        Self::from_slice(data)
            .map_err(|e| km_err!(InvalidKeyBlob, "failed to parse keyblob: {:?}", e))
    }

    pub fn secure_deletion_slot(&self) -> Option<SecureDeletionSlot> {
        match self {
            EncryptedKeyBlob::V1(blob) => blob.secure_deletion_slot,
        }
    }

    pub fn kek_context(&self) -> &[u8] {
        match self {
            EncryptedKeyBlob::V1(blob) => &blob.kek_context,
        }
    }
}

impl AsCborValue for EncryptedKeyBlob {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let mut a = match value {
            cbor::value::Value::Array(a) if a.len() == 2 => a,
            _ => return cbor_type_error(&value, "arr len 2"),
        };
        let inner = a.remove(1);
        let version = Version::from_cbor_value(a.remove(0))?;
        match version {
            Version::V1 => Ok(Self::V1(EncryptedKeyBlobV1::from_cbor_value(inner)?)),
        }
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(match self {
            EncryptedKeyBlob::V1(inner) => cbor::value::Value::Array(
                vec_try![Version::V1.to_cbor_value()?, inner.to_cbor_value()?]
                    .map_err(|_e| CborError::AllocationFailed)?,
            ),
        })
    }
    fn cddl_typename() -> Option<String> {
        Some("EncryptedKeyBlob".to_string())
    }
    fn cddl_schema() -> Option<String> {
        Some(format!(
            "&(
    [{}, {}] ; Version::V1
)",
            Version::V1 as i32,
            EncryptedKeyBlobV1::cddl_ref()
        ))
    }
}

#[derive(Clone, Debug, AsCborValue)]
pub struct EncryptedKeyBlobV1 {
    pub characteristics: Vec<KeyCharacteristics>,

    pub key_derivation_input: [u8; 32],

    pub kek_context: Vec<u8>,

    pub encrypted_key_material: coset::CoseEncrypt0,

    pub secure_deletion_slot: Option<SecureDeletionSlot>,
}

pub trait LegacyKeyHandler: Send {
    fn is_legacy_key(&self, keyblob: &[u8], params: &[KeyParam], root_of_trust: &BootInfo) -> bool {
        match self.convert_legacy_key(
            keyblob,
            params,
            root_of_trust,
            SecurityLevel::TrustedEnvironment,
        ) {
            Ok(_blob) => true,
            Err(e) => {
                info!("legacy keyblob conversion attempt failed: {e:?}");
                false
            }
        }
    }

    fn convert_legacy_key(
        &self,
        keyblob: &[u8],
        params: &[KeyParam],
        root_of_trust: &BootInfo,
        sec_level: SecurityLevel,
    ) -> Result<PlaintextKeyBlob, Error>;

    fn delete_legacy_key(&mut self, keyblob: &[u8]) -> Result<(), Error>;
}

#[derive(Clone, PartialEq, Eq, AsCborValue, ZeroizeOnDrop)]
pub struct SecureDeletionData {
    pub factory_reset_secret: [u8; 32],

    pub secure_deletion_secret: [u8; 16],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SlotPurpose {
    KeyGeneration,

    KeyImport,

    KeyUpgrade,
}

pub trait SecureDeletionSecretManager: Send {
    fn get_or_create_factory_reset_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
    ) -> Result<SecureDeletionData, Error>;

    fn get_factory_reset_secret(&self) -> Result<SecureDeletionData, Error>;

    fn new_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
        purpose: SlotPurpose,
    ) -> Result<(SecureDeletionSlot, SecureDeletionData), Error>;

    fn get_secret(&self, slot: SecureDeletionSlot) -> Result<SecureDeletionData, Error>;

    fn delete_secret(&mut self, slot: SecureDeletionSlot) -> Result<(), Error>;

    fn delete_all(&mut self);
}

struct SlotHolder<'a> {
    mgr: &'a mut dyn SecureDeletionSecretManager,

    slot: Option<SecureDeletionSlot>,
}

impl Drop for SlotHolder<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            if let Err(e) = self.mgr.delete_secret(slot) {
                error!("Failed to delete recently-acquired SDD slot {slot:?}: {e:?}");
            }
        }
    }
}

impl<'a> SlotHolder<'a> {
    fn new(
        mgr: &'a mut dyn SecureDeletionSecretManager,
        rng: &mut dyn crypto::Rng,
        purpose: SlotPurpose,
    ) -> Result<(Self, SecureDeletionData), Error> {
        let (slot, sdd) = mgr.new_secret(rng, purpose)?;
        Ok((
            Self {
                mgr,
                slot: Some(slot),
            },
            sdd,
        ))
    }

    fn consume(mut self) -> SecureDeletionSlot {
        self.slot.take().unwrap()
    }
}

#[derive(Debug, Clone, AsCborValue)]
pub struct RootOfTrustInfo {
    pub verified_boot_key: Vec<u8>,

    pub device_boot_locked: bool,

    pub verified_boot_state: VerifiedBootState,
}

pub fn derive_kek(
    kdf: &dyn crypto::Hkdf,
    root_key: &crypto::OpaqueOr<crypto::hmac::Key>,
    key_derivation_input: &[u8; 32],
    characteristics: Vec<KeyCharacteristics>,
    hidden: Vec<KeyParam>,
    sdd: Option<SecureDeletionData>,
) -> Result<crypto::OpaqueOr<crypto::aes::Key>, Error> {
    let mut info = try_to_vec(key_derivation_input)?;
    info.try_extend_from_slice(&characteristics.into_vec()?)?;
    info.try_extend_from_slice(&hidden.into_vec()?)?;
    if let Some(sdd) = sdd {
        info.try_extend_from_slice(&sdd.into_vec()?)?;
    }

    match root_key {
        crypto::OpaqueOr::Explicit(key_material) => {
            kdf.hkdf_aes(&[], &key_material.0, &info, aes::Variant::Aes256)
        }
        key @ crypto::OpaqueOr::Opaque(_) => kdf.expand_aes(key, &info, aes::Variant::Aes256),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaintextKeyBlob {
    pub characteristics: Vec<KeyCharacteristics>,

    pub key_material: crypto::KeyMaterial,
}

impl PlaintextKeyBlob {
    pub fn characteristics_at(&self, sec_level: SecurityLevel) -> Result<&[KeyParam], Error> {
        tag::characteristics_at(&self.characteristics, sec_level)
    }

    pub fn suitable_for(&self, purpose: KeyPurpose, sec_level: SecurityLevel) -> Result<(), Error> {
        if contains_tag_value!(self.characteristics_at(sec_level)?, Purpose, purpose) {
            Ok(())
        } else {
            Err(km_err!(
                IncompatiblePurpose,
                "purpose {:?} not supported by keyblob",
                purpose
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    sec_level: SecurityLevel,
    sdd_mgr: Option<&mut dyn SecureDeletionSecretManager>,
    aes: &dyn crypto::Aes,
    kdf: &dyn crypto::Hkdf,
    rng: &mut dyn crypto::Rng,
    root_key: &crypto::OpaqueOr<crypto::hmac::Key>,
    kek_context: &[u8],
    plaintext_keyblob: PlaintextKeyBlob,
    hidden: Vec<KeyParam>,
    purpose: SlotPurpose,
) -> Result<EncryptedKeyBlob, Error> {
    let requires_sdd = plaintext_keyblob
        .characteristics_at(sec_level)?
        .iter()
        .any(|param| {
            matches!(
                param,
                KeyParam::RollbackResistance | KeyParam::UsageCountLimit(1)
            )
        });
    let (slot_holder, sdd) = match (requires_sdd, sdd_mgr) {
        (true, Some(sdd_mgr)) => {
            let (holder, sdd) = SlotHolder::new(sdd_mgr, rng, purpose)?;
            (Some(holder), Some(sdd))
        }
        (true, None) => {
            return Err(km_err!(
                RollbackResistanceUnavailable,
                "no secure secret storage available"
            ))
        }
        (false, Some(sdd_mgr)) => (None, Some(sdd_mgr.get_or_create_factory_reset_secret(rng)?)),
        (false, None) => (None, None),
    };
    let characteristics = plaintext_keyblob.characteristics;
    let mut key_derivation_input = [0u8; 32];
    rng.fill_bytes(&mut key_derivation_input[..]);
    let kek = derive_kek(
        kdf,
        root_key,
        &key_derivation_input,
        characteristics.clone(),
        hidden,
        sdd,
    )?;

    let cose_encrypt = coset::CoseEncrypt0Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::A256GCM)
                .build(),
        )
        .try_create_ciphertext::<_, Error>(
            &plaintext_keyblob.key_material.into_vec()?,
            &[],
            move |pt, aad| {
                let mut op = aes.begin_aead(
                    kek,
                    crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
                    crypto::SymmetricOperation::Encrypt,
                )?;
                op.update_aad(aad)?;
                let mut ct = op.update(pt)?;
                ct.try_extend_from_slice(&op.finish()?)?;
                Ok(ct)
            },
        )?
        .build();

    Ok(EncryptedKeyBlob::V1(EncryptedKeyBlobV1 {
        characteristics,
        key_derivation_input,
        kek_context: try_to_vec(kek_context)?,
        encrypted_key_material: cose_encrypt,
        secure_deletion_slot: slot_holder.map(|h| h.consume()),
    }))
}

pub fn decrypt(
    sdd_mgr: Option<&dyn SecureDeletionSecretManager>,
    aes: &dyn crypto::Aes,
    kdf: &dyn crypto::Hkdf,
    root_key: &crypto::OpaqueOr<crypto::hmac::Key>,
    encrypted_keyblob: EncryptedKeyBlob,
    hidden: Vec<KeyParam>,
) -> Result<PlaintextKeyBlob, Error> {
    let EncryptedKeyBlob::V1(encrypted_keyblob) = encrypted_keyblob;
    let sdd = match (encrypted_keyblob.secure_deletion_slot, sdd_mgr) {
        (Some(slot), Some(sdd_mgr)) => Some(sdd_mgr.get_secret(slot)?),
        (Some(_slot), None) => {
            return Err(km_err!(
                InvalidKeyBlob,
                "keyblob has sdd slot but no secure storage available"
            ))
        }
        (None, Some(sdd_mgr)) => Some(sdd_mgr.get_factory_reset_secret()?),
        (None, None) => None,
    };
    let characteristics = encrypted_keyblob.characteristics;
    let kek = derive_kek(
        kdf,
        root_key,
        &encrypted_keyblob.key_derivation_input,
        characteristics.clone(),
        hidden,
        sdd,
    )?;
    let cose_encrypt = encrypted_keyblob.encrypted_key_material;

    let extended_aad = coset::enc_structure_data(
        coset::EncryptionContext::CoseEncrypt0,
        cose_encrypt.protected.clone(),
        &[],
    );

    let mut op = aes.begin_aead(
        kek,
        crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
        crypto::SymmetricOperation::Decrypt,
    )?;
    op.update_aad(&extended_aad)?;
    let mut pt_data = op.update(&cose_encrypt.ciphertext.unwrap_or_default())?;
    pt_data.try_extend_from_slice(
        &op.finish()
            .map_err(|e| km_err!(InvalidKeyBlob, "failed to decrypt keyblob: {:?}", e))?,
    )?;

    Ok(PlaintextKeyBlob {
        characteristics,
        key_material: <crypto::KeyMaterial>::from_slice(&pt_data)?,
    })
}
