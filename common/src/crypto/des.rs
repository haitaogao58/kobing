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

pub const BLOCK_SIZE: usize = 8;

pub const KEY_SIZE_BITS: KeySizeInBits = KeySizeInBits(168);

pub const KEY_SIZE_BYTES: usize = 24;

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Key(pub [u8; KEY_SIZE_BYTES]);

impl Key {
    pub fn new(data: Vec<u8>) -> Result<Key, Error> {
        Ok(Key(data.try_into().map_err(|_e| {
            km_err!(UnsupportedKeySize, "3-DES key size wrong")
        })?))
    }

    pub fn new_from(data: &[u8]) -> Result<Key, Error> {
        let data = try_to_vec(data)?;
        Ok(Key(data.try_into().map_err(|_e| {
            km_err!(UnsupportedKeySize, "3-DES key size wrong")
        })?))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    EcbNoPadding,

    EcbPkcs7Padding,

    CbcNoPadding { nonce: [u8; BLOCK_SIZE] },

    CbcPkcs7Padding { nonce: [u8; BLOCK_SIZE] },
}
