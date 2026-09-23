use std::{
    cell::RefCell,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex, Once, OnceLock, RwLock,
    },
};

use rsbinder::Strong;

use anyhow::{Context, Result};

use crate::{
    android::hardware::security::secureclock::ISecureClock::ISecureClock,
    err,
    keymaster::{
        apex::ModuleInfoBundle, async_task::AsyncTask, db::KeymasterDb, enforcements::Enforcements,
        gc::Gc, keymint_device::get_keymint_wrapper, super_key::SuperKeyManager,
        utils::get_interface_once,
    },
    plat::property_watcher::PropertyWatcher,
    watchdog as wd,
};

static DB_INIT: Once = Once::new();
const KOBING_DB_ROOT: &str = "/data/surprise/waste/data";
const DB_ORPHAN_LIMIT: usize = 100_000;

pub fn db_root_path() -> &'static Path {
    Path::new(KOBING_DB_ROOT)
}

pub static ASYNC_TASK: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);

static GC: LazyLock<Arc<Gc>> = LazyLock::new(|| {
    Arc::new(Gc::new_init_with(ASYNC_TASK.clone(), || {
        (
            Box::new(|uuid, blob| {
                let security_level = uuid.to_security_level().unwrap();

                let km_dev = get_keymint_wrapper(security_level).unwrap();
                let _wp = wd::watch("invalidate key closure: calling IKeyMintDevice::deleteKey");
                km_dev
                    .delete_Key(blob)
                    .map_err(|e| anyhow::anyhow!("Failed to delete key blob: {e}"))
                    .context(err!("Trying to invalidate key blob."))
            }),
            KeymasterDb::new(db_root_path(), None).expect("Failed to open database"),
            SUPER_KEY.clone(),
        )
    }))
});

pub fn create_thread_local_db() -> KeymasterDb {
    let result = KeymasterDb::new(db_root_path(), Some(GC.clone()));
    let mut db = match result {
        Ok(db) => db,
        Err(e) => {
            log::error!(
                "Failed to open Keystore database at {:?}: {e:?}",
                db_root_path()
            );
            log::error!("Has /data been mounted correctly?");
            panic!("Failed to open database for Keystore, cannot continue: {e:?}")
        }
    };

    DB_INIT.call_once(|| {
        log::info!("Touching Keystore 2.0 database for this first time since boot.");
        log::info!("Calling cleanup_leftovers({DB_ORPHAN_LIMIT}).");
        let n = db
            .cleanup_leftovers(DB_ORPHAN_LIMIT)
            .expect("Failed to cleanup database on startup");
        if n != 0 {
            log::info!(
                "Cleaned up {n} failed entries, indicating keystore crash on key generation"
            );
        }
    });
    db
}

thread_local! {




    pub static DB: RefCell<KeymasterDb> = RefCell::new(create_thread_local_db());
}

pub static ENFORCEMENTS: LazyLock<Enforcements> = LazyLock::new(Default::default);

pub static SUPER_KEY: LazyLock<Arc<RwLock<SuperKeyManager>>> = LazyLock::new(Default::default);

static BOOT_COMPLETED: AtomicBool = AtomicBool::new(false);

pub fn boot_completed() -> bool {
    BOOT_COMPLETED.load(Ordering::Acquire)
}

pub fn await_boot_completed() {
    let _wp = wd::watch_millis("await_boot_completed", 300_000);
    log::info!("monitoring for sys.boot_completed=1");
    while let Err(e) = watch_for_boot_completed() {
        log::error!("failed to watch for boot_completed: {e:?}");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    BOOT_COMPLETED.store(true, Ordering::Release);
    log::info!("wait_for_boot_completed done, triggering GC");
    GC.notify_gc();
}

fn watch_for_boot_completed() -> Result<()> {
    let watcher =
        PropertyWatcher::new("sys.boot_completed").context(err!("PropertyWatcher::new failed"))?;
    loop {
        let value = watcher
            .read()
            .context(err!("Failed to read sys.boot_completed"))?;
        if value == "1" {
            return Ok(());
        }
        watcher
            .wait(Some(&value))
            .context(err!("Failed to wait for sys.boot_completed"))?;
    }
}

pub static MODULE_INFO_BUNDLE: OnceLock<ModuleInfoBundle> = OnceLock::new();

pub fn install_module_info_bundle(bundle: ModuleInfoBundle) -> Result<()> {
    MODULE_INFO_BUNDLE
        .set(bundle)
        .map_err(|_| anyhow::anyhow!("APEX module info bundle was already initialized"))
}

pub fn module_info_bundle() -> Option<&'static ModuleInfoBundle> {
    MODULE_INFO_BUNDLE.get()
}

static TIME_STAMP_DEVICE: Mutex<Option<Strong<dyn ISecureClock>>> = Mutex::new(None);

pub fn get_timestamp_service() -> Result<Strong<dyn ISecureClock>> {
    let mut ts_device = TIME_STAMP_DEVICE.lock().unwrap();
    if let Some(dev) = &*ts_device {
        Ok(dev.clone())
    } else {
        let dev = connect_secureclock().context(err!())?;
        *ts_device = Some(dev.clone());
        Ok(dev)
    }
}

fn connect_secureclock() -> Result<Strong<dyn ISecureClock>> {
    let descriptors = <crate::android::hardware::security::secureclock::ISecureClock::BpSecureClock as ISecureClock>::descriptor();
    let dev: Strong<dyn ISecureClock> = get_interface_once(descriptors).context(err!())?;

    Ok(dev)
}

pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;
