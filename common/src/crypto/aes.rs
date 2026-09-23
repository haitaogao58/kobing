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

use crate::{km_err, try_to_vec, Error};
use core::convert::TryInto;
use kmr_wire::KeySizeInBits;
use std::vec::Vec;
use zeroize::ZeroizeOnDrop;

pub const BLOCK_SIZE: usize = 16;

pub const GCM_NONCE_SIZE: usize = 12;

#[derive(Clone)]
pub enum Variant {
    Aes128,

    Aes192,

    Aes256,
}

impl Variant {
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum Key {
    Aes128([u8; 16]),

    Aes192([u8; 24]),

    Aes256([u8; 32]),
}

impl Key {
    pub fn new(data: Vec<u8>) -> Result<Self, Error> {
        match data.len() {
            16 => Ok(Key::Aes128(data.try_into().unwrap())),
            24 => Ok(Key::Aes192(data.try_into().unwrap())),
            32 => Ok(Key::Aes256(data.try_into().unwrap())),
            l => Err(km_err!(
                UnsupportedKeySize,
                "AES keys must be 16, 24 or 32 bytes not {}",
                l
            )),
        }
    }

    pub fn new_from(data: &[u8]) -> Result<Self, Error> {
        Key::new(try_to_vec(data)?)
    }

    pub fn size(&self) -> KeySizeInBits {
        KeySizeInBits(match self {
            Key::Aes128(_) => 128,
            Key::Aes192(_) => 192,
            Key::Aes256(_) => 256,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CipherMode {
    EcbNoPadding,

    EcbPkcs7Padding,

    CbcNoPadding { nonce: [u8; BLOCK_SIZE] },

    CbcPkcs7Padding { nonce: [u8; BLOCK_SIZE] },

    Ctr { nonce: [u8; BLOCK_SIZE] },
}

#[derive(Clone, Copy, Debug)]
pub enum GcmMode {
    GcmTag12 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag13 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag14 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag15 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag16 { nonce: [u8; GCM_NONCE_SIZE] },
}

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Cipher(CipherMode),

    Aead(GcmMode),
}

impl Mode {
    pub fn is_aead(&self) -> bool {
        match self {
            Mode::Aead(_) => true,
            Mode::Cipher(_) => false,
        }
    }
}

impl GcmMode {
    pub fn tag_len(&self) -> usize {
        match self {
            GcmMode::GcmTag12 { nonce: _ } => 12,
            GcmMode::GcmTag13 { nonce: _ } => 13,
            GcmMode::GcmTag14 { nonce: _ } => 14,
            GcmMode::GcmTag15 { nonce: _ } => 15,
            GcmMode::GcmTag16 { nonce: _ } => 16,
        }
    }
}
