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

use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

static OPERATION_PERFORMED: LazyLock<Mutex<HashSet<SecurityLevel>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn notify_operation_performed(sl: SecurityLevel) {
    OPERATION_PERFORMED.lock().unwrap().insert(sl);
}

pub fn was_operation_performed(sl: SecurityLevel) -> bool {
    OPERATION_PERFORMED.lock().unwrap().contains(&sl)
}

pub fn reset(sl: SecurityLevel) {
    OPERATION_PERFORMED.lock().unwrap().remove(&sl);
}
