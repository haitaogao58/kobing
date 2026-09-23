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

use super::*;
use crate::{crypto::ec::Key, der_err, explicit, keyblob, vec_try, Error};
use der::Decode;
use kmr_wire::{keymint, keymint::Digest, KeySizeInBits, RsaExponent};
use log::{error, warn};
use std::{boxed::Box, vec::Vec};

pub struct Implementation {
    pub rng: Box<dyn Rng>,

    pub clock: Option<Box<dyn MonotonicClock>>,

    pub compare: Box<dyn ConstTimeEq>,

    pub aes: Box<dyn Aes>,

    pub des: Box<dyn Des>,

    pub hmac: Box<dyn Hmac>,

    pub rsa: Box<dyn Rsa>,

    pub ec: Box<dyn Ec>,

    pub ckdf: Box<dyn Ckdf>,

    pub hkdf: Box<dyn Hkdf>,

    pub sha256: Box<dyn Sha256>,

    pub mldsa: Box<dyn MlDsa>,
}

pub trait Rng: Send {
    fn add_entropy(&mut self, data: &[u8]);

    fn fill_bytes(&mut self, dest: &mut [u8]);

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

pub trait ConstTimeEq: Send {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool;

    fn ne(&self, left: &[u8], right: &[u8]) -> bool {
        !self.eq(left, right)
    }
}

pub trait MonotonicClock: Send {
    fn now(&self) -> MillisecondsSinceEpoch;
}

pub trait Aes: Send {
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        variant: aes::Variant,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        Ok(match variant {
            aes::Variant::Aes128 => {
                let mut key = [0; 16];
                rng.fill_bytes(&mut key[..]);
                KeyMaterial::Aes(aes::Key::Aes128(key).into())
            }
            aes::Variant::Aes192 => {
                let mut key = [0; 24];
                rng.fill_bytes(&mut key[..]);
                KeyMaterial::Aes(aes::Key::Aes192(key).into())
            }
            aes::Variant::Aes256 => {
                let mut key = [0; 32];
                rng.fill_bytes(&mut key[..]);
                KeyMaterial::Aes(aes::Key::Aes256(key).into())
            }
        })
    }

    fn import_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<(KeyMaterial, KeySizeInBits), Error> {
        let aes_key = aes::Key::new_from(data)?;
        let key_size = aes_key.size();
        Ok((KeyMaterial::Aes(aes_key.into()), key_size))
    }

    fn begin(
        &self,
        key: OpaqueOr<aes::Key>,
        mode: aes::CipherMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error>;

    fn begin_aead(
        &self,
        key: OpaqueOr<aes::Key>,
        mode: aes::GcmMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, Error>;
}

pub trait Des: Send {
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        let mut key = vec_try![0; 24]?;

        rng.fill_bytes(&mut key[..]);
        Ok(KeyMaterial::TripleDes(des::Key::new(key)?.into()))
    }

    fn import_key(&self, data: &[u8], _params: &[keymint::KeyParam]) -> Result<KeyMaterial, Error> {
        let des_key = des::Key::new_from(data)?;
        Ok(KeyMaterial::TripleDes(des_key.into()))
    }

    fn begin(
        &self,
        key: OpaqueOr<des::Key>,
        mode: des::Mode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error>;
}

pub trait Hmac: Send {
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        key_size: KeySizeInBits,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        hmac::valid_hal_size(key_size)?;

        let key_len = (key_size.0 / 8) as usize;
        let mut key = vec_try![0; key_len]?;
        rng.fill_bytes(&mut key);
        Ok(KeyMaterial::Hmac(hmac::Key::new(key).into()))
    }

    fn import_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<(KeyMaterial, KeySizeInBits), Error> {
        let hmac_key = hmac::Key::new_from(data)?;
        let key_size = hmac_key.size();
        hmac::valid_hal_size(key_size)?;
        Ok((KeyMaterial::Hmac(hmac_key.into()), key_size))
    }

    fn begin(
        &self,
        key: OpaqueOr<hmac::Key>,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

pub trait AesCmac: Send {
    fn begin(&self, key: OpaqueOr<aes::Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

pub trait Rsa: Send {
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        key_size: KeySizeInBits,
        pub_exponent: RsaExponent,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    fn import_pkcs8_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<(KeyMaterial, KeySizeInBits, RsaExponent), Error> {
        rsa::import_pkcs8_key(data)
    }

    fn subject_public_key(&self, key: &OpaqueOr<rsa::Key>) -> Result<Vec<u8>, Error> {
        let rsa_key = explicit!(key)?;
        rsa_key.subject_public_key()
    }

    fn begin_decrypt(
        &self,
        key: OpaqueOr<rsa::Key>,
        mode: rsa::DecryptionMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;

    fn begin_sign(
        &self,
        key: OpaqueOr<rsa::Key>,
        mode: rsa::SignMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

pub trait Ec: Send {
    fn generate_nist_key(
        &self,
        rng: &mut dyn Rng,
        curve: ec::NistCurve,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    fn generate_ed25519_key(
        &self,
        rng: &mut dyn Rng,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    fn generate_x25519_key(
        &self,
        rng: &mut dyn Rng,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    fn import_pkcs8_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        ec::import_pkcs8_key(data)
    }

    fn import_raw_ed25519_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        ec::import_raw_ed25519_key(data)
    }

    fn import_raw_x25519_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        ec::import_raw_x25519_key(data)
    }

    fn subject_public_key(&self, key: &OpaqueOr<ec::Key>) -> Result<Vec<u8>, Error> {
        let ec_key = explicit!(key)?;
        match ec_key {
            Key::P224(nist_key)
            | Key::P256(nist_key)
            | Key::P384(nist_key)
            | Key::P521(nist_key) => {
                let ec_pvt_key = sec1::EcPrivateKey::from_der(nist_key.0.as_slice())
                    .map_err(|e| der_err!(e, "failed to parse DER NIST EC PrivateKey"))?;
                match ec_pvt_key.public_key {
                    Some(pub_key) => Ok(pub_key.to_vec()),
                    None => {
                        let nist_curve: ec::NistCurve = ec_key.curve().try_into()?;
                        Ok(self.nist_public_key(nist_key, nist_curve)?)
                    }
                }
            }
            Key::Ed25519(ed25519_key) => self.ed25519_public_key(ed25519_key),
            Key::X25519(x25519_key) => self.x25519_public_key(x25519_key),
        }
    }

    fn nist_public_key(&self, key: &ec::NistKey, curve: ec::NistCurve) -> Result<Vec<u8>, Error>;

    fn ed25519_public_key(&self, key: &ec::Ed25519Key) -> Result<Vec<u8>, Error>;

    fn x25519_public_key(&self, key: &ec::X25519Key) -> Result<Vec<u8>, Error>;

    fn begin_agree(&self, key: OpaqueOr<ec::Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;

    fn begin_sign(
        &self,
        key: OpaqueOr<ec::Key>,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

pub trait MlDsa: Send {
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        variant: MlDsaVariant,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        let mut key = [0; mldsa::SEED_SIZE];
        rng.fill_bytes(&mut key[..]);
        let key = match variant {
            MlDsaVariant::MlDsa65 => mldsa::Key::MlDsa65(key),
            MlDsaVariant::MlDsa87 => mldsa::Key::MlDsa87(key),
        };
        Ok(KeyMaterial::MlDsa(variant, key.into()))
    }

    fn import_raw_key(
        &self,
        data: &[u8],
        variant: MlDsaVariant,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        mldsa::import_raw_key(data, variant)
    }

    fn import_pkcs8_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        mldsa::import_pkcs8_key(data)
    }

    fn subject_public_key(&self, key: &OpaqueOr<mldsa::Key>) -> Result<Vec<u8>, Error>;

    fn begin_sign(
        &self,
        key: OpaqueOr<mldsa::Key>,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

pub trait EmittingOperation: Send {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

pub trait AadOperation: EmittingOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error>;
}

pub trait AccumulatingOperation: Send {
    fn max_input_size(&self) -> Option<usize> {
        None
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

pub trait Hkdf: Send {
    fn hkdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
        let prk = self.extract(salt, ikm)?;
        self.expand(&prk, info, out_len)
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error>;

    fn expand(
        &self,
        prk: &OpaqueOr<hmac::Key>,
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error>;

    fn hkdf_aes(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        variant: aes::Variant,
    ) -> Result<OpaqueOr<aes::Key>, Error> {
        let data = self.hkdf(salt, ikm, info, variant.key_size())?;
        let explicit_key = aes::Key::new(data)?;
        Ok(explicit_key.into())
    }

    fn expand_aes(
        &self,
        prk: &OpaqueOr<hmac::Key>,
        info: &[u8],
        variant: aes::Variant,
    ) -> Result<OpaqueOr<aes::Key>, Error> {
        let data = self.expand(prk, info, variant.key_size())?;
        let explicit_key = aes::Key::new(data)?;
        Ok(explicit_key.into())
    }
}

pub trait Ckdf: Send {
    fn ckdf(
        &self,
        key: &OpaqueOr<aes::Key>,
        label: &[u8],
        chunks: &[&[u8]],
        out_len: usize,
    ) -> Result<Vec<u8>, Error>;
}

pub trait Sha256: Send {
    fn hash(&self, data: &[u8]) -> Result<[u8; 32], Error>;
}

#[macro_export]
macro_rules! log_unimpl {
    () => {
        error!(
            "{}:{}: Unimplemented placeholder KeyMint trait method invoked!",
            file!(),
            line!(),
        );
    };
}

#[macro_export]
macro_rules! unimpl {
    () => {
        log_unimpl!();
        return Err($crate::km_err!(Unimplemented, "method unimplemented"));
    };
}

pub struct NoOpRng;
impl Rng for NoOpRng {
    fn add_entropy(&mut self, _data: &[u8]) {
        log_unimpl!();
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        log_unimpl!();
    }
}

#[derive(Clone)]
pub struct InsecureEq;
impl ConstTimeEq for InsecureEq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        warn!("Insecure comparison operation performed");
        left == right
    }
}

pub struct NoOpClock;
impl MonotonicClock for NoOpClock {
    fn now(&self) -> MillisecondsSinceEpoch {
        log_unimpl!();
        MillisecondsSinceEpoch(0)
    }
}

pub struct NoOpAes;
impl Aes for NoOpAes {
    fn begin(
        &self,
        _key: OpaqueOr<aes::Key>,
        _mode: aes::CipherMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error> {
        unimpl!();
    }
    fn begin_aead(
        &self,
        _key: OpaqueOr<aes::Key>,
        _mode: aes::GcmMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpDes;
impl Des for NoOpDes {
    fn begin(
        &self,
        _key: OpaqueOr<des::Key>,
        _mode: des::Mode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpHmac;
impl Hmac for NoOpHmac {
    fn begin(
        &self,
        _key: OpaqueOr<hmac::Key>,
        _digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpAesCmac;
impl AesCmac for NoOpAesCmac {
    fn begin(&self, _key: OpaqueOr<aes::Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpRsa;
impl Rsa for NoOpRsa {
    fn generate_key(
        &self,
        _rng: &mut dyn Rng,
        _key_size: KeySizeInBits,
        _pub_exponent: RsaExponent,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn begin_decrypt(
        &self,
        _key: OpaqueOr<rsa::Key>,
        _mode: rsa::DecryptionMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: OpaqueOr<rsa::Key>,
        _mode: rsa::SignMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpEc;
impl Ec for NoOpEc {
    fn generate_nist_key(
        &self,
        _rng: &mut dyn Rng,
        _curve: ec::NistCurve,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn generate_ed25519_key(
        &self,
        _rng: &mut dyn Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn generate_x25519_key(
        &self,
        _rng: &mut dyn Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn nist_public_key(&self, _key: &ec::NistKey, _curve: ec::NistCurve) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn ed25519_public_key(&self, _key: &ec::Ed25519Key) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn x25519_public_key(&self, _key: &ec::X25519Key) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn begin_agree(
        &self,
        _key: OpaqueOr<ec::Key>,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: OpaqueOr<ec::Key>,
        _digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpMlDsa;
impl MlDsa for NoOpMlDsa {
    fn subject_public_key(&self, _key: &OpaqueOr<mldsa::Key>) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: OpaqueOr<mldsa::Key>,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpSdsManager;
impl keyblob::SecureDeletionSecretManager for NoOpSdsManager {
    fn get_or_create_factory_reset_secret(
        &mut self,
        _rng: &mut dyn Rng,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }

    fn get_factory_reset_secret(&self) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }

    fn new_secret(
        &mut self,
        _rng: &mut dyn Rng,
        _purpose: keyblob::SlotPurpose,
    ) -> Result<(keyblob::SecureDeletionSlot, keyblob::SecureDeletionData), Error> {
        unimpl!();
    }

    fn get_secret(
        &self,
        _slot: keyblob::SecureDeletionSlot,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }
    fn delete_secret(&mut self, _slot: keyblob::SecureDeletionSlot) -> Result<(), Error> {
        unimpl!();
    }

    fn delete_all(&mut self) {
        log_unimpl!();
    }
}
