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

use crate::keymaster::async_task::AsyncTask;
use crate::keymaster::db::{KeystoreDB, SupersededBlob, Uuid};
use crate::keymaster::super_key::SuperKeyManager;
use crate::{err as ks_err, global};
use anyhow::{Context, Result};
use log::error;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, RwLock,
};

type InvalidateKey = Box<dyn Fn(&Uuid, &[u8]) -> Result<()> + Send + 'static>;

pub struct Gc {
    async_task: Arc<AsyncTask>,
    notified: Arc<AtomicU8>,
}

impl Gc {
    pub fn new_init_with<F>(async_task: Arc<AsyncTask>, init: F) -> Self
    where
        F: FnOnce() -> (InvalidateKey, KeystoreDB, Arc<RwLock<SuperKeyManager>>) + Send + 'static,
    {
        let weak_at = Arc::downgrade(&async_task);
        let notified = Arc::new(AtomicU8::new(0));
        let notified_clone = notified.clone();

        async_task.queue_hi(move |shelf| {
            let (invalidate_key, db, super_key) = init();
            let notified = notified_clone;
            shelf.get_or_put_with(|| GcInternal {
                deleted_blob_ids: vec![],
                superseded_blobs: vec![],
                invalidate_key,
                db,
                async_task: weak_at,
                super_key,
                notified,
            });
        });
        Self {
            async_task,
            notified,
        }
    }

    pub fn notify_gc(&self) {
        if let Ok(0) = self
            .notified
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
        {
            self.async_task
                .queue_lo(|shelf| shelf.get_downcast_mut::<GcInternal>().unwrap().step())
        }
    }
}

struct GcInternal {
    deleted_blob_ids: Vec<i64>,
    superseded_blobs: Vec<SupersededBlob>,
    invalidate_key: InvalidateKey,
    db: KeystoreDB,
    async_task: std::sync::Weak<AsyncTask>,
    super_key: Arc<RwLock<SuperKeyManager>>,
    notified: Arc<AtomicU8>,
}

impl GcInternal {
    fn process_one_key(&mut self) -> Result<()> {
        if self.superseded_blobs.is_empty() {
            let blobs = self
                .db
                .handle_next_superseded_blobs(&self.deleted_blob_ids, 20)
                .context(ks_err!("Trying to handle superseded blob."))?;
            self.deleted_blob_ids = vec![];
            self.superseded_blobs = blobs;
        }

        if let Some(SupersededBlob {
            blob_id,
            blob,
            metadata,
        }) = self.superseded_blobs.pop()
        {
            self.deleted_blob_ids.push(blob_id);

            if let Some(uuid) = metadata.km_uuid() {
                let blob = self
                    .super_key
                    .read()
                    .unwrap()
                    .unwrap_key_if_required_with_ko_bing_compatibility(&metadata, &blob)
                    .context(ks_err!("Trying to unwrap to-be-deleted blob.",))?;
                (self.invalidate_key)(uuid, &blob).context(ks_err!("Trying to invalidate key."))?;
            }
        }
        Ok(())
    }

    fn step(&mut self) {
        self.notified.store(0, Ordering::Relaxed);
        if !global::boot_completed() {
            log::info!("skip GC as boot not completed");
            return;
        }
        if let Err(e) = self.process_one_key() {
            error!("Error trying to delete blob entry: {e:?}");
        }

        if !self.deleted_blob_ids.is_empty() {
            if let Some(at) = self.async_task.upgrade() {
                if let Ok(0) =
                    self.notified
                        .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                {
                    at.queue_lo(move |shelf| {
                        shelf.get_downcast_mut::<GcInternal>().unwrap().step()
                    });
                }
            }
        }
    }
}
