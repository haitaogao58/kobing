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
    Algorithm::Algorithm, Digest::Digest, KeyParameter::KeyParameter as KmKeyParameter,
    KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use crate::err;
use crate::keymaster::db::{KeyType, KeymasterDb};
use crate::keymaster::key_parameter::KeyParameterValue;
use crate::keymaster::keymint_device::KeyMintDevice;
use anyhow::{Context, Result};
use kmr_common::crypto::AES_256_KEY_LENGTH;
use kmr_crypto_boring::km::{hkdf_expand, ko_bing_legacy_kdf_expand};
use kmr_crypto_boring::zvec::ZVec;
use log::{error, info};
use std::collections::VecDeque;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootLevel(pub usize);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum DenyLaterStrategy {
    MaxUsesPerBoot,

    EarlyBootOnly,
}

const PROPERTY_NAME: &str = "ro.keystore.boot_level_key.strategy";
static LEVEL_ZERO_SELECTION: OnceLock<(SecurityLevel, DenyLaterStrategy)> = OnceLock::new();

fn lookup_level_zero_km_and_strategy() -> Result<Option<(SecurityLevel, DenyLaterStrategy)>> {
    let property_val: Result<String, rsproperties::Error> = rsproperties::get(PROPERTY_NAME);

    let property_val = if let Ok(p) = property_val {
        p
    } else {
        info!(
            "{} not set, inferring from installed KM instances",
            PROPERTY_NAME
        );
        return Ok(None);
    };
    let (level, strategy) = if let Some(c) = property_val.split_once(':') {
        c
    } else {
        error!("Missing colon in {PROPERTY_NAME}: {property_val:?}");
        return Ok(None);
    };
    let level = match level {
        "TRUSTED_ENVIRONMENT" => SecurityLevel::TRUSTED_ENVIRONMENT,
        "STRONGBOX" => SecurityLevel::STRONGBOX,
        _ => {
            error!("Unknown security level in {PROPERTY_NAME}: {level:?}");
            return Ok(None);
        }
    };
    let strategy = match strategy {
        "EARLY_BOOT_ONLY" => DenyLaterStrategy::EarlyBootOnly,
        "MAX_USES_PER_BOOT" => DenyLaterStrategy::MaxUsesPerBoot,
        _ => {
            error!(
                "Unknown DenyLaterStrategy in {}: {:?}",
                PROPERTY_NAME, strategy
            );
            return Ok(None);
        }
    };
    info!("Set from {PROPERTY_NAME}: {property_val}");
    Ok(Some((level, strategy)))
}

fn get_level_zero_key_km_and_strategy() -> Result<(KeyMintDevice, DenyLaterStrategy)> {
    let &(level, strategy) = LEVEL_ZERO_SELECTION.get_or_try_init(|| -> Result<_> {
        if let Some((level, strategy)) = lookup_level_zero_km_and_strategy()? {
            return Ok((level, strategy));
        }
        let tee = KeyMintDevice::get(SecurityLevel::TRUSTED_ENVIRONMENT)
            .context(err!("Get TEE instance failed."))?;
        if tee.version() >= KeyMintDevice::KEY_MASTER_V4_1 {
            Ok((
                SecurityLevel::TRUSTED_ENVIRONMENT,
                DenyLaterStrategy::EarlyBootOnly,
            ))
        } else {
            match KeyMintDevice::get_or_none(SecurityLevel::STRONGBOX)
                .context(err!("Get Strongbox instance failed."))?
            {
                Some(strongbox) if strongbox.version() >= KeyMintDevice::KEY_MASTER_V4_1 => {
                    Ok((SecurityLevel::STRONGBOX, DenyLaterStrategy::EarlyBootOnly))
                }
                _ => Ok((
                    SecurityLevel::TRUSTED_ENVIRONMENT,
                    DenyLaterStrategy::MaxUsesPerBoot,
                )),
            }
        }
    })?;

    Ok((
        KeyMintDevice::get(level).context(err!("Get KM instance failed."))?,
        strategy,
    ))
}

pub fn get_level_zero_key(db: &mut KeymasterDb) -> Result<ZVec> {
    let (km_dev, deny_later_strategy) =
        get_level_zero_key_km_and_strategy().context(err!("get preferred KM instance failed"))?;
    info!(
        "In get_level_zero_key: security_level={:?}, deny_later_strategy={:?}",
        km_dev.security_level(),
        deny_later_strategy
    );
    let required_security_level = km_dev.security_level();
    let required_param: KmKeyParameter = match deny_later_strategy {
        DenyLaterStrategy::EarlyBootOnly => KeyParameterValue::EarlyBootOnly,
        DenyLaterStrategy::MaxUsesPerBoot => KeyParameterValue::MaxUsesPerBoot(1),
    }
    .into();
    let params = vec![
        KeyParameterValue::Algorithm(Algorithm::HMAC).into(),
        KeyParameterValue::Digest(Digest::SHA_2_256).into(),
        KeyParameterValue::KeySize(256).into(),
        KeyParameterValue::MinMacLength(256).into(),
        KeyParameterValue::KeyPurpose(KeyPurpose::SIGN).into(),
        KeyParameterValue::NoAuthRequired.into(),
        required_param.clone(),
    ];

    let key_desc = KeyMintDevice::internal_descriptor("boot_level_key".to_string());
    let (key_id_guard, key_entry) = km_dev
        .lookup_or_generate_key(
            db,
            &key_desc,
            KeyType::Client,
            &params,
            |key_characteristics| {
                key_characteristics.iter().any(|kc| {
                    if kc.securityLevel != required_security_level {
                        error!(
                            "In get_level_zero_key: security level expected={:?} got={:?}",
                            required_security_level, kc.securityLevel
                        );
                        return false;
                    }
                    if !kc.authorizations.iter().any(|a| a == &required_param) {
                        error!(
                            "In get_level_zero_key: required param absent {:?}",
                            required_param
                        );
                        return false;
                    }
                    true
                })
            },
        )
        .context(err!("lookup_or_generate_key failed"))?;

    let params = [
        KeyParameterValue::MacLength(256).into(),
        KeyParameterValue::Digest(Digest::SHA_2_256).into(),
    ];
    let level_zero_key = km_dev
        .use_key_in_one_step(
            db,
            &key_id_guard,
            crate::keymaster::keymint_device::OneStepKeyOperation {
                key_blob: &key_entry,
                purpose: KeyPurpose::SIGN,
                parameters: &params,
                auth_token: None,
                input: b"Create boot level key",
            },
        )
        .context(err!("use_key_in_one_step failed"))?;

    let level_zero_key =
        ZVec::try_from(level_zero_key).context(err!("conversion to ZVec failed"))?;
    Ok(level_zero_key)
}

pub struct BootLevelKeyCache {
    current: BootLevel,

    cache: VecDeque<ZVec>,
}

impl BootLevelKeyCache {
    const HKDF_ADVANCE: &'static [u8] = b"Advance KDF one step";
    const HKDF_AES: &'static [u8] = b"Generate AES-256-GCM key";
    const HKDF_KEY_SIZE: usize = 32;

    pub fn new(level_zero_key: ZVec) -> Self {
        let mut cache: VecDeque<ZVec> = VecDeque::new();
        cache.push_back(level_zero_key);
        Self {
            current: BootLevel(0),
            cache,
        }
    }

    pub fn level_accessible(&self, boot_level: BootLevel) -> bool {
        boot_level >= self.current && !self.cache.is_empty()
    }

    fn get_hkdf_key(&mut self, boot_level: BootLevel) -> Result<Option<&ZVec>> {
        if !self.level_accessible(boot_level) {
            return Ok(None);
        }

        let first_not_cached = self.current.0 + self.cache.len();

        for _level in first_not_cached..=boot_level.0 {
            let highest_key = self.cache.back().unwrap();
            let next_key = hkdf_expand(Self::HKDF_KEY_SIZE, highest_key, Self::HKDF_ADVANCE)
                .context(err!("Advancing key one step"))?;
            self.cache.push_back(next_key);
        }

        Ok(Some(self.cache.get(boot_level.0 - self.current.0).unwrap()))
    }

    pub fn advance_boot_level(&mut self, new_boot_level: BootLevel) -> Result<()> {
        if !self.level_accessible(new_boot_level) {
            error!(
                "Failed to advance boot level to {new_boot_level:?}, current is {:?}, cache size {}",
                self.current,
                self.cache.len()
            );
            return Ok(());
        }

        self.get_hkdf_key(new_boot_level)
            .context(err!("Advancing cache"))?;

        self.cache = self.cache.split_off(new_boot_level.0 - self.current.0);

        self.current = new_boot_level;

        Ok(())
    }

    pub fn finish(&mut self) {
        self.cache.clear();
    }

    fn expand_key(
        &mut self,
        boot_level: BootLevel,
        out_len: usize,
        info: &[u8],
    ) -> Result<Option<ZVec>> {
        self.get_hkdf_key(boot_level)
            .context(err!("Looking up HKDF key"))?
            .map(|k| hkdf_expand(out_len, k, info))
            .transpose()
            .context(err!("Calling hkdf_expand"))
    }

    pub fn aes_key(&mut self, boot_level: BootLevel) -> Result<Option<ZVec>> {
        self.expand_key(boot_level, AES_256_KEY_LENGTH, BootLevelKeyCache::HKDF_AES)
            .context(err!("expand_key failed"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_output_is_consistent() -> Result<()> {
        let initial_key = b"initial key";
        let mut blkc = BootLevelKeyCache::new(ZVec::try_from(initial_key as &[u8])?);
        assert!(blkc.level_accessible(BootLevel(0)));
        assert!(blkc.level_accessible(BootLevel(9)));
        assert!(blkc.level_accessible(BootLevel(10)));
        assert!(blkc.level_accessible(BootLevel(100)));
        let v0 = blkc.aes_key(BootLevel(0)).unwrap().unwrap();
        let v10 = blkc.aes_key(BootLevel(10)).unwrap().unwrap();
        assert_eq!(Some(&v0), blkc.aes_key(BootLevel(0))?.as_ref());
        assert_eq!(Some(&v10), blkc.aes_key(BootLevel(10))?.as_ref());
        blkc.advance_boot_level(BootLevel(5))?;
        assert!(!blkc.level_accessible(BootLevel(0)));
        assert!(blkc.level_accessible(BootLevel(9)));
        assert!(blkc.level_accessible(BootLevel(10)));
        assert!(blkc.level_accessible(BootLevel(100)));
        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
        assert_eq!(Some(&v10), blkc.aes_key(BootLevel(10))?.as_ref());
        blkc.advance_boot_level(BootLevel(10))?;
        assert!(!blkc.level_accessible(BootLevel(0)));
        assert!(!blkc.level_accessible(BootLevel(9)));
        assert!(blkc.level_accessible(BootLevel(10)));
        assert!(blkc.level_accessible(BootLevel(100)));
        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
        assert_eq!(Some(&v10), blkc.aes_key(BootLevel(10))?.as_ref());
        blkc.advance_boot_level(BootLevel(0))?;
        assert!(!blkc.level_accessible(BootLevel(0)));
        assert!(!blkc.level_accessible(BootLevel(9)));
        assert!(blkc.level_accessible(BootLevel(10)));
        assert!(blkc.level_accessible(BootLevel(100)));
        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
        assert_eq!(Some(v10), blkc.aes_key(BootLevel(10))?);
        blkc.finish();
        assert!(!blkc.level_accessible(BootLevel(0)));
        assert!(!blkc.level_accessible(BootLevel(9)));
        assert!(!blkc.level_accessible(BootLevel(10)));
        assert!(!blkc.level_accessible(BootLevel(100)));
        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
        assert_eq!(None, blkc.aes_key(BootLevel(10))?);
        Ok(())
    }
}

pub(crate) struct LegacyBootLevelKeyCache {
    current: BootLevel,
    cache: VecDeque<ZVec>,
}

impl LegacyBootLevelKeyCache {
    pub(crate) fn new(level_zero_key: ZVec) -> Self {
        let mut cache = VecDeque::new();
        cache.push_back(level_zero_key);
        Self {
            current: BootLevel(0),
            cache,
        }
    }

    fn level_accessible(&self, boot_level: BootLevel) -> bool {
        boot_level >= self.current && !self.cache.is_empty()
    }

    fn get_hkdf_key(&mut self, boot_level: BootLevel) -> Result<Option<&ZVec>> {
        if !self.level_accessible(boot_level) {
            return Ok(None);
        }
        let first_not_cached = self.current.0 + self.cache.len();
        for _level in first_not_cached..=boot_level.0 {
            let highest_key = self.cache.back().unwrap();
            let next_key = ko_bing_legacy_kdf_expand(
                BootLevelKeyCache::HKDF_KEY_SIZE,
                highest_key,
                BootLevelKeyCache::HKDF_ADVANCE,
            )
            .context(err!("Advancing legacy key one step"))?;
            self.cache.push_back(next_key);
        }
        Ok(Some(self.cache.get(boot_level.0 - self.current.0).unwrap()))
    }

    pub(crate) fn advance_boot_level(&mut self, new_boot_level: BootLevel) -> Result<()> {
        if !self.level_accessible(new_boot_level) {
            return Ok(());
        }
        self.get_hkdf_key(new_boot_level)
            .context(err!("Advancing legacy cache"))?;
        self.cache = self.cache.split_off(new_boot_level.0 - self.current.0);
        self.current = new_boot_level;
        Ok(())
    }

    pub(crate) fn finish(&mut self) {
        self.cache.clear();
    }

    pub(crate) fn aes_key(&mut self, boot_level: BootLevel) -> Result<Option<ZVec>> {
        self.get_hkdf_key(boot_level)
            .context(err!("Looking up legacy KDF key"))?
            .map(|key| {
                ko_bing_legacy_kdf_expand(AES_256_KEY_LENGTH, key, BootLevelKeyCache::HKDF_AES)
            })
            .transpose()
            .context(err!("Calling legacy KDF expand"))
    }
}

#[cfg(test)]
mod ko_bing_test {
    use super::*;

    #[test]
    fn legacy_cache_is_independent() -> Result<()> {
        let initial_key = b"initial key";
        let mut current = BootLevelKeyCache::new(ZVec::try_from(initial_key as &[u8])?);
        let mut legacy = LegacyBootLevelKeyCache::new(ZVec::try_from(initial_key as &[u8])?);
        assert_ne!(
            current.aes_key(BootLevel(10))?.unwrap(),
            legacy.aes_key(BootLevel(10))?.unwrap()
        );
        legacy.advance_boot_level(BootLevel(10))?;
        assert_eq!(None, legacy.aes_key(BootLevel(0))?);
        legacy.finish();
        assert_eq!(None, legacy.aes_key(BootLevel(10))?);
        assert!(current.aes_key(BootLevel(0))?.is_some());
        Ok(())
    }
}
