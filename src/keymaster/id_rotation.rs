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

use crate::err as ks_err;

use anyhow::{Context, Result};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const ID_ROTATION_PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60);
static TIMESTAMP_FILE_NAME: &str = "timestamp";

#[derive(Debug, Clone)]
pub struct IdRotationState {
    timestamp_path: PathBuf,
}

impl IdRotationState {
    pub fn new(keystore_db_path: &Path) -> Self {
        let mut timestamp_path = keystore_db_path.to_owned();
        timestamp_path.push(TIMESTAMP_FILE_NAME);
        Self { timestamp_path }
    }

    pub fn had_factory_reset_since_id_rotation(
        &self,
        creation_datetime: &SystemTime,
    ) -> Result<bool> {
        match fs::metadata(&self.timestamp_path) {
            Ok(metadata) => {
                let temporal_counter_value = creation_datetime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .context(ks_err!("Failed to get epoch time"))?
                    .as_millis()
                    / ID_ROTATION_PERIOD.as_millis();

                let id_rotation_time: SystemTime = SystemTime::UNIX_EPOCH
                    .checked_add(ID_ROTATION_PERIOD * temporal_counter_value.try_into()?)
                    .context(ks_err!("Failed to get ID rotation time."))?;

                let factory_reset_time = metadata
                    .modified()
                    .context(ks_err!("File creation time not supported."))?;

                Ok(id_rotation_time <= factory_reset_time)
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    fs::File::create(&self.timestamp_path)
                        .context(ks_err!("Failed to create timestamp file."))?;
                    Ok(true)
                }
                _ => Err(e).context(ks_err!("Failed to open timestamp file.")),
            },
        }
        .context(ks_err!())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nix::sys::stat::utimes;
    use nix::sys::time::{TimeVal, TimeValLike};
    use std::thread::sleep;
    use tempfile::TempDir;

    static TEMP_DIR_NAME: &str = "test_had_factory_reset_since_id_rotation_";

    fn set_up() -> (TempDir, PathBuf, IdRotationState) {
        let temp_dir = tempfile::Builder::new()
            .prefix(TEMP_DIR_NAME)
            .tempdir()
            .expect("Failed to create temp dir.");
        let mut timestamp_file_path = temp_dir.path().to_owned();
        timestamp_file_path.push(TIMESTAMP_FILE_NAME);
        let id_rotation_state = IdRotationState::new(temp_dir.path());

        (temp_dir, timestamp_file_path, id_rotation_state)
    }

    #[test]
    fn test_timestamp_creation() {
        let (_temp_dir, timestamp_file_path, id_rotation_state) = set_up();
        let creation_datetime = SystemTime::now();

        assert!(!timestamp_file_path.exists());

        sleep(Duration::new(1, 0));
        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        assert!(timestamp_file_path.exists());

        let metadata = fs::metadata(&timestamp_file_path).unwrap();
        assert!(metadata.modified().unwrap() > creation_datetime);
    }

    #[test]
    fn test_existing_timestamp() {
        let (_temp_dir, timestamp_file_path, id_rotation_state) = set_up();

        let mut creation_datetime = SystemTime::UNIX_EPOCH;

        fs::File::create(&timestamp_file_path).unwrap();
        let mtime = TimeVal::seconds(0);
        let atime = TimeVal::seconds(0);
        utimes(&timestamp_file_path, &atime, &mtime).unwrap();

        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        creation_datetime += Duration::from_millis(1);

        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        creation_datetime += ID_ROTATION_PERIOD;

        assert!(!id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        let mtime = TimeVal::seconds((ID_ROTATION_PERIOD.as_secs() * 10).try_into().unwrap());
        let atime = TimeVal::seconds((ID_ROTATION_PERIOD.as_secs() * 10).try_into().unwrap());
        utimes(&timestamp_file_path, &atime, &mtime).unwrap();
        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());
    }
}
