use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::{
    file_watch::{self, WatchTrigger},
    fs::atomic_replace_preserving_metadata,
    retry::{retry_read_race, ReadRaceErrorKind, RetryOutcome},
};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/keystore/ko_bing/injector.toml";
/// Authoritative package allow-list file (one package per line).
pub const DEFAULT_BM_PATH: &str = "/data/surprise/kobing_bm.txt";
const CURRENT_CONFIG_VERSION: u32 = 1;
const REPLACE_SAVE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const REPLACE_SAVE_RETRY_LIMIT: usize = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InjectorConfig {
    pub version: u32,
    /// Package allow-list. The authoritative source is `bm.txt` (one package
    /// per line); the legacy `scoop = [...]` array in `injector.toml` is still
    /// accepted for migration but is never written back.
    pub scoop: Vec<String>,
    pub main: MainConfig,
    pub filter: FilterConfig,
    pub intercept: InterceptConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct MainConfig {
    pub enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    pub enabled: bool,
    pub deny_packages: Vec<String>,
    pub block_android_package: bool,
    pub allow_unknown_package: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct InterceptConfig {
    pub get_security_level: bool,
    pub get_key_entry: bool,
    pub update_subcomponent: bool,
    pub list_entries: bool,
    pub delete_key: bool,
    pub grant: bool,
    pub ungrant: bool,
    pub get_number_of_entries: bool,
    pub list_entries_batched: bool,
    pub get_supplementary_attestation_info: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            scoop: default_scoop(),
            main: MainConfig::default(),
            filter: FilterConfig::default(),
            intercept: InterceptConfig::default(),
        }
    }
}

fn default_scoop() -> Vec<String> {
    [
        "io.github.vvb2060.keyattestation",
        "com.google.android.gsf",
        "com.google.android.gms",
        "com.android.vending",
        "com.eltavine.duckdetector",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "debug".to_string(),
        }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_packages: Vec::new(),
            block_android_package: true,
            allow_unknown_package: false,
        }
    }
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            get_security_level: true,
            get_key_entry: true,
            update_subcomponent: true,
            list_entries: true,
            delete_key: true,
            grant: true,
            ungrant: true,
            get_number_of_entries: true,
            list_entries_batched: true,
            get_supplementary_attestation_info: true,
        }
    }
}

#[derive(Debug)]
enum LoadError {
    Missing(io::Error),
    Io(io::Error),
    Parse(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(error) | Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LoadContext {
    Startup,
    Reload(WatchTrigger),
}

 
#[derive(Deserialize)]
struct ConfigVersion {
    version: Option<toml::Spanned<i64>>,
}

#[derive(Serialize)]
struct WritableConfig<'a> {
    version: u32,
    main: &'a MainConfig,
    filter: &'a FilterConfig,
    intercept: &'a InterceptConfig,
}

static CONFIG: OnceLock<RwLock<Arc<InjectorConfig>>> = OnceLock::new();
static WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static CONFIG_FILE_WRITE_LOCK: Mutex<()> = Mutex::new(());

impl LoadContext {
    fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Reload(trigger) => trigger.label(),
        }
    }
}

pub fn get() -> Arc<InjectorConfig> {
    if CONFIG.get().is_none() || WATCHER_STARTED.get().is_none() {
        ensure_initialized();
    }
    Arc::clone(
        &CONFIG
            .get()
            .expect("injector config should be initialized")
            .read()
            .expect("injector config lock poisoned"),
    )
}

fn ensure_initialized() {
    let path = config_path();
    CONFIG.get_or_init(|| {
        RwLock::new(Arc::new(
            load_or_seed(&path, LoadContext::Startup)
                .expect("startup config loading always returns a fallback"),
        ))
    });
    WATCHER_STARTED.get_or_init(|| {
        start_watcher(path);
        start_bm_watcher();
    });
}
fn config_path() -> PathBuf {
    std::env::var_os("KOBING_INJECTOR_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}
fn bm_path() -> PathBuf {
    std::env::var_os("KOBING_INJECTOR_BM_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BM_PATH))
}
fn has_legacy_scoop_key(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("scoop") && trimmed.contains('=')
    })
}
fn read_bm_packages(path: &Path) -> io::Result<Vec<String>> {
    let contents = fs::read_to_string(path)?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}
fn write_bm_packages(path: &Path, packages: &[String]) -> io::Result<()> {
    let mut contents = String::new();
    for package in normalize_packages(packages.to_vec()) {
        contents.push_str(&package);
        contents.push('\n');
    }
    let (default_uid, default_gid) = default_bm_owner(path);
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o644, default_uid, default_gid)
}
fn default_bm_owner(path: &Path) -> (u32, u32) {
    if path == Path::new(DEFAULT_BM_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
}

fn load_from_path(path: &Path, allow_migration: bool) -> Result<InjectorConfig, LoadError> {
    load_from_path_with_bm(path, allow_migration, &bm_path())
}

/// Same as [`load_from_path`] but with an explicit bm.txt path so tests can
/// isolate the real package allow-list on disk.
fn load_from_path_with_bm(
    path: &Path,
    allow_migration: bool,
    bm: &Path,
) -> Result<InjectorConfig, LoadError> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| LoadError::Io(io::Error::other("config file write lock poisoned")))?;
    let contents = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LoadError::Missing(error)
        } else {
            LoadError::Io(error)
        }
    })?;
    let (mut config, migrated_contents) =
        parse_versioned_config(&contents, allow_migration).map_err(LoadError::Parse)?;

    // The package allow-list lives in bm.txt, not in injector.toml.
    match read_bm_packages(bm) {
        Ok(packages) => config.scoop = normalize_packages(packages),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // First run without bm.txt: keep the legacy `scoop` array and seed
            // bm.txt from it so the package list survives the transition.
            if config.scoop.is_empty() {
                config.scoop = default_scoop();
            }
            if allow_migration {
                match write_bm_packages(bm, &config.scoop) {
                    Ok(()) => log::info!("seeded bm.txt at {}", bm.display()),
                    Err(write_error) => log::error!(
                        "failed to seed bm.txt at {}: {}",
                        bm.display(),
                        write_error
                    ),
                }
            }
        }
        Err(error) => {
            log::warn!(
                "failed to read bm.txt at {}: {}; keeping package list from injector.toml",
                bm.display(),
                error
            );
        }
    }

    if let Some(migrated_contents) = migrated_contents {
        let (default_uid, default_gid) = default_owner(path);
        atomic_replace_preserving_metadata(
            path,
            migrated_contents.as_bytes(),
            0o600,
            default_uid,
            default_gid,
        )
        .map_err(LoadError::Io)?;
        log::info!("migrated injector.toml to version {CURRENT_CONFIG_VERSION}");
    } else if allow_migration && has_legacy_scoop_key(&contents) {
        // Drop the stale `scoop` array now that packages are read from bm.txt.
        let cleaned = render_config(&config).map_err(LoadError::Io)?;
        let (default_uid, default_gid) = default_owner(path);
        atomic_replace_preserving_metadata(
            path,
            cleaned.as_bytes(),
            0o600,
            default_uid,
            default_gid,
        )
        .map_err(LoadError::Io)?;
        log::info!("removed legacy `scoop` array from injector.toml (packages now in bm.txt)");
    }
    Ok(config)
}

fn load_with_context(
    path: &Path,
    context: LoadContext,
) -> Result<RetryOutcome<InjectorConfig>, LoadError> {
    match context {
        LoadContext::Reload(trigger) if trigger.should_retry_reads() => load_with_read_race_retry(
            path,
            context,
            |path| load_from_path(path, false),
            std::thread::sleep,
        ),
        LoadContext::Startup => {
            load_from_path(path, true).map(|value| RetryOutcome { value, retries: 0 })
        }
        LoadContext::Reload(_) => {
            load_from_path(path, false).map(|value| RetryOutcome { value, retries: 0 })
        }
    }
}

fn load_or_seed(path: &Path, context: LoadContext) -> Option<InjectorConfig> {
    match load_with_context(path, context) {
        Ok(loaded) => {
            if loaded.retries > 0 {
                log::info!(
                    "{} config load from {} succeeded after {} retr{}",
                    context.label(),
                    path.display(),
                    loaded.retries,
                    if loaded.retries == 1 { "y" } else { "ies" }
                );
            }
            if matches!(context, LoadContext::Startup) {
                log::info!(
                    "loaded config from {} via {}",
                    path.display(),
                    context.label()
                );
            }
            Some(loaded.value)
        }
        Err(LoadError::Missing(error)) if matches!(context, LoadContext::Startup) => {
            log::warn!(
                "config missing at {} during startup: {}; seeding defaults",
                path.display(),
                error
            );
            let mut config = InjectorConfig::default();
            if let Err(write_error) = write_config(path, &config) {
                log::error!(
                    "failed to seed config at {}: {}; disabling injector",
                    path.display(),
                    write_error
                );
                config.main.enabled = false;
            }
            Some(config)
        }
        Err(error) => {
            log::warn!(
                "load from {} via {} failed: {}; keeping current config",
                path.display(),
                context.label(),
                error
            );
            if matches!(context, LoadContext::Startup) {
                let mut config = current_config_snapshot();
                config.main.enabled = false;
                Some(config)
            } else {
                None
            }
        }
    }
}

fn current_config_snapshot() -> InjectorConfig {
    match CONFIG.get() {
        Some(lock) => match lock.read() {
            Ok(config) => config.as_ref().clone(),
            Err(error) => {
                log::error!("current config lock poisoned while snapshotting: {}", error);
                InjectorConfig::default()
            }
        },
        None => InjectorConfig::default(),
    }
}

fn write_config(path: &Path, config: &InjectorConfig) -> io::Result<()> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| io::Error::other("config file write lock poisoned"))?;
    let contents = render_config(config)?;
    let (default_uid, default_gid) = default_owner(path);
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, default_uid, default_gid)?;
    log::info!("wrote config to {}", path.display());
    Ok(())
}

fn default_owner(path: &Path) -> (u32, u32) {
    if path == Path::new(DEFAULT_CONFIG_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
}

fn render_config(config: &InjectorConfig) -> io::Result<String> {
    let mut contents = String::from(
        "# Package allow-list lives in bm.txt (one package per line).\n\
         # With `[filter].enabled = true`, a UID is intercepted when any package\n\
         # sharing that UID is listed there.\n\
         # Filter deny settings still apply to every package resolved for the UID.\n\n",
    );
    let base = toml::to_string_pretty(&WritableConfig {
        version: config.version,
        main: &config.main,
        filter: &config.filter,
        intercept: &config.intercept,
    })
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    contents.push_str(&base);
    Ok(contents)
}
#[cfg(test)]
fn parse_config(contents: &str) -> Result<InjectorConfig, String> {
    parse_versioned_config(contents, true).map(|(config, _)| config)
}

fn parse_versioned_config(
    contents: &str,
    allow_migration: bool,
) -> Result<(InjectorConfig, Option<String>), String> {
    let without_bom = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let bom_len = contents.len() - without_bom.len();
    let version: ConfigVersion =
        toml::from_str(without_bom).map_err(|error| error.to_string())?;
    let migrated = match version.version {
        None => {
            if !allow_migration {
                return Err(
                    "injector config version 0 requires an injector restart to migrate".into(),
                );
            }
            Some(insert_config_version(contents, bom_len))
        }
        Some(version) => match *version.get_ref() {
            0 if allow_migration => {
                let span = version.span();
                let mut migrated = contents.to_string();
                migrated.replace_range(span.start + bom_len..span.end + bom_len, "1");
                Some(migrated)
            }
            0 => {
                return Err(
                    "injector config version 0 requires an injector restart to migrate".into(),
                )
            }
            version if version == i64::from(CURRENT_CONFIG_VERSION) => None,
            version if version < 0 => {
                return Err(format!("config version must not be negative: {version}"))
            }
            version => {
                return Err(format!(
                "config version {version} is newer than supported version {CURRENT_CONFIG_VERSION}"
            ))
            }
        },
    };
    let candidate = migrated.as_deref().unwrap_or(contents);
    let candidate = candidate.strip_prefix('\u{feff}').unwrap_or(candidate);
    let parsed: InjectorConfig =
        toml::from_str(candidate).map_err(|error| error.to_string())?;
    Ok((parsed.normalized(), migrated))
}

fn insert_config_version(contents: &str, bom_len: usize) -> String {
    let newline = if contents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut migrated = String::with_capacity(contents.len() + 12);
    migrated.push_str(&contents[..bom_len]);
    migrated.push_str("version = 1");
    migrated.push_str(newline);
    migrated.push_str(&contents[bom_len..]);
    migrated
}

fn normalize_packages(packages: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for package in packages {
        let package = package.trim();
        if !package.is_empty() && seen.insert(package.to_string()) {
            normalized.push(package.to_string());
        }
    }
    normalized
}

 
fn start_watcher(path: PathBuf) {
    let reload_path = path.clone();
    if let Err(error) =
        file_watch::spawn_path_watcher("injector-config-watch", path, move |trigger| {
            reload_runtime_config(&reload_path, trigger);
        })
    {
        log::error!("failed to start config watcher thread: {}", error);
    }
}
fn start_bm_watcher() {
    let bm = bm_path();
    let reload_path = config_path();
    if let Err(error) =
        file_watch::spawn_path_watcher("injector-bm-watch", bm, move |trigger| {
            reload_runtime_config(&reload_path, trigger);
        })
    {
        log::error!("failed to start bm.txt watcher thread: {}", error);
    }
}

fn reload_runtime_config(path: &Path, trigger: WatchTrigger) {
    let Some(config) = load_or_seed(path, LoadContext::Reload(trigger)) else {
        return;
    };
    if let Some(lock) = CONFIG.get() {
        match lock.write() {
            Ok(mut guard) => {
                let level = config.main.log_level_filter();
                *guard = Arc::new(config);
                log::set_max_level(level);
                log::info!(
                    "reloaded config from {} via {}",
                    path.display(),
                    trigger.label()
                );
            }
            Err(error) => {
                log::error!(
                    "failed to apply config reload from {}: {}",
                    path.display(),
                    error
                );
            }
        }
    }
}

fn load_with_read_race_retry<F, S>(
    path: &Path,
    context: LoadContext,
    mut loader: F,
    sleeper: S,
) -> Result<RetryOutcome<InjectorConfig>, LoadError>
where
    F: FnMut(&Path) -> Result<InjectorConfig, LoadError>,
    S: FnMut(Duration),
{
    retry_read_race(
        || loader(path),
        |error| match error {
            LoadError::Missing(_) | LoadError::Io(_) => ReadRaceErrorKind::Retryable,
            LoadError::Parse(_) => ReadRaceErrorKind::Fatal,
        },
        REPLACE_SAVE_RETRY_LIMIT,
        REPLACE_SAVE_RETRY_INTERVAL,
        sleeper,
        |retries, error, interval| {
            log::warn!(
                "{} config load from {} hit read-side race on retry {}/{}: {}; waiting {} ms",
                context.label(),
                path.display(),
                retries,
                REPLACE_SAVE_RETRY_LIMIT,
                error,
                interval.as_millis()
            );
        },
    )
}

pub fn parse_level_filter(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

impl MainConfig {
    pub fn log_level_filter(&self) -> LevelFilter {
        parse_level_filter(&self.log_level).unwrap_or(LevelFilter::Debug)
    }
}

impl InjectorConfig {
    fn normalized(mut self) -> Self {
        self.scoop = normalize_packages(self.scoop);
        self
    }
}

#[cfg(test)]
mod tests;
