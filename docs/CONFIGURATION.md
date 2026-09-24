# Configuration Guide
**English** | [简体中文](CONFIGURATION.zh-CN.md) | [繁體中文](CONFIGURATION.zh-TW.md)

KoBing (KOBING) uses three active configuration files:

- `/data/surprise/waste/config.toml` — the KeyMint service itself, the identity it
  reports, and the secrets used for KOBING-created keys.
- `/data/surprise/injector.toml` — decides which KeyStore requests go to KOBING.
- `/data/surprise/bm.txt` — the apps that are allowed to use KOBING.

This guide is about the configuration that is actually live on your device. Each
example is followed by a separate field-by-field reference, so the short comments
in the examples don't have to say everything — the field notes are the source of
truth.

**Jump to:** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml) | [`bm.txt`](#bmtxt)

## Before editing

For day-to-day use, there's really only one thing you need to touch: the package
names in `bm.txt`. Leave `injector.toml`, the safety filters, the `[intercept]`
switches, and the generated `[crypto]` values alone.

Before you change anything:

1. Keep a private backup of the live files.
2. Edit the files under `/data/surprise/` (and `/data/surprise/waste/`), not the
   copies inside the module ZIP.
3. Keep strings quoted and booleans as `true` / `false`, and put package names in
   `bm.txt` — one full name per line.

Change one thing at a time, save the whole file, then check the matching log.

Never share your `[crypto]` values, IMEI, IMEI2, MEID, serial numbers, or an
unredacted copy of any live file.

## How changes are loaded

Both components watch their own live file, but they don't behave the same way:

- A valid change to `injector.toml` or `bm.txt` takes effect for new requests
  right away, no restart.
- `config.toml` is read automatically, but only the four patch-level fields and
  the biometric compatibility switch can fully take effect without restarting
  keymint. Each field below says when a restart is needed.
- If a running component is handed a malformed file, it rejects the file and
  keeps the last valid config it has in memory.
- If `config.toml` is broken when keymint starts, keymint won't start. Fix the
  file and restart keymint.
- If `injector.toml` is broken when the injector starts, KOBING routing stays
  off. Save a valid file and the watcher brings routing back on its own;
  restart the injector only if it really won't recover.
- If a file is missing at startup, KOBING creates a new one with generated
  defaults. Don't treat that as a "factory reset" — the regenerated secrets
  can't bring back keys protected by the old ones.

Restart commands are in
[Restarting keymint and injector](../README.md#restarting-keymint-and-injector).
After changing routing, close and reopen the affected app so an operation that's
already open doesn't fight the new route. If you just want a clean boundary,
restarting the injector is enough; an injector-only change doesn't need a keymint
restart.

## `config.toml`

### Complete annotated example

The `[crypto]` values below are deliberately broken placeholders — they do
nothing. A real live file has unique generated hex values. Don't paste these
placeholders onto a device, and don't overwrite values that are already in the
file. The `[trust]` and `[device]` values are examples too: unless you actually
mean to change the reported identity, keep whatever the live file already has.

```toml
# Configuration format. Keep this at 2.
version = 2

[main]
# The only supported service backend. Don't change it.
backend = "injector"
# KeyMint log detail: off, error, warn, info, debug, or trace.
log_level = "debug"
# Insecure biometric compatibility switch. Keep false for normal use.
force_skip_system_biometric_hat_verification = false

[crypto]
# Redacted placeholders only. Keep the real 64-character values.
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# Optional expert override. Normally just delete this line.
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# Detect the Android major at each keymint start; an integer pins it.
os_version = "auto"
# auto, latest, or an exact YYYY-MM-DD; boot also takes a decimal u32.
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# auto, random, or exactly 64 hex characters.
vb_key = "auto"
vb_hash = "auto"
# Report verified boot and a locked bootloader when true.
verified_boot_state = true
device_locked = true

[device]
# Device identity strings reported when an app asks for attestation IDs.
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# false fills only empty telephony fields, and only when the device has a value.
overrideTelephonyProperties = false
# Empty optional identifiers are fine; don't make up values.
meid = ""
imei = ""
imei2 = ""
```

### Top-level field

#### `version`

This is the config format version, and the only value is the integer `2`. It has
nothing to do with your Android version or the KOBING release number. Don't bump
it — just leave the file's value alone. A live reload with any other value is
rejected, and the last valid runtime config keeps running.

If `version` is missing at keymint startup, it's treated as `0`. Versions `0` and
`1` get migrated in place to `2` before the service starts, and `os_version` is
set to `"auto"` so a later Android upgrade is picked up on the next keymint start.
Startup also deletes the obsolete `trust_record`. For version `0`, missing
patch-level fields inherit the configured `security_patch`; other configured and
unknown values are left as-is. Live reload doesn't migrate anything, so an older
file needs a keymint restart to upgrade. A future version that isn't recognized
is never overwritten.

### `[main]`

#### `backend`

Just use `"injector"`. It's the only supported choice and there's no alternative
runtime backend, so don't change it.

#### `log_level`

This sets what keymint writes to the log. Pick one of `"off"`, `"error"`,
`"warn"`, `"info"`, `"debug"`, or `"trace"`. The default is `"debug"`, which is
also the best level for a bug report. `"trace"` is noisier; `"off"` silences
normal logging.

Changing this needs a keymint restart. An unrecognized value falls back to
`debug`, but don't count on that — it can quietly hide a typo.

#### `force_skip_system_biometric_hat_verification`

An insecure compatibility switch for devices whose System KeyMint can't verify
biometric authentication tokens properly. Turn it `true` and KOBING will accept a
token whose structure is valid without asking System KeyMint to check its
authentication code.

Keep it `false` unless a maintainer has confirmed a device-specific problem. It
doesn't hide root, and it's not a cure-all for fingerprint or lock-screen issues.
A valid save applies to new checks right away, with no keymint restart.

### `[crypto]`

Every value in this section is secret. Each one is exactly 32 bytes, written as
64 hex characters (`0-9`, `a-f`). KOBING generates them when it creates a new
config.

Keep all four seed and nonce fields present and unchanged, and back them up
privately along with the KOBING data. Change or remove any of them and you'll
need a keymint restart — and you'll likely break existing keys or any operation
bound to authentication. Don't swap in values from another device, and don't use
the placeholders in this guide as replacements.

If `shared_secret_seed` or `shared_secret_nonce` goes missing, KOBING randomly
regenerates it when it reads the file. That's no longer a stable live config, so
keep both values present.

#### `root_kek_seed`

Seeds the key material that protects KOBING key blobs. If it changes, KOBING may
no longer be able to open keys created with the old value. It must be present and
must not change.

#### `kak_seed`

Seeds KOBING's key-agreement protection. It belongs to the same device-secret set
as `root_kek_seed`. It must be present and must not change.

#### `shared_secret_seed`

The seed half of the shared secret used to verify authentication tokens. Keep it
together with `shared_secret_nonce` — change just one half and the final secret
changes anyway.

#### `shared_secret_nonce`

The nonce half of that shared secret. It's also a full 64-character hex value —
not a short counter, and nothing you regenerate by hand.

#### `auth_token_hmac_key`

An optional explicit HMAC key for authentication tokens. Leave this field out and
KOBING derives the key from `shared_secret_seed` plus `shared_secret_nonce`. Most
people should just not write this line. If you do set it explicitly, it must also
be exactly 64 hex characters, and it must stay private and unchanged.

### `[trust]`

This section controls the values reported through key attestation. It doesn't
repair hardware, renew a certificate, undo a keybox revocation, or hide root.

#### `os_version`

Use `"auto"` to detect the current Android major every time the keymint process
starts, or an integer from `0` to `99` to pin one, like `12`, `16`, or `17`.
Don't put a dotted release, an SDK number, or a security patch date here. KeyMint
encodes the resolved major with the AOSP `MMmmss` formula, so a pinned `16` is
reported as `160000`. Changing this needs a keymint restart.

#### `security_patch`

Controls `ro.build.version.security_patch`. It accepts:

- `"auto"`: use the current `ro.build.version.security_patch` without writing it;
- `"latest"`: the fifth of the current calendar month, as of when the value is
  resolved; or
- an actual date as `"YYYY-MM-DD"`, with leading zeroes.

For `"auto"`, KOBING first uses a nonempty runtime property, then the exact key
from the standard `build.prop` locations, and finally `2025-06-05` if neither
source exists. A value already present at runtime is used as-is, not replaced by a
`build.prop` value. `"latest"` and an exact date deliberately overwrite the
runtime property, but KOBING never creates or deletes it. `"auto"` never writes
the property. In the same boot, after an explicit override or `"latest"`,
switching back to `"auto"` keeps the current runtime value; reboot to get the
system value back.

#### `os_patchlevel`

Controls the KeyMint OS patch level. `"auto"` follows the effective
`security_patch`; `"latest"` and an exact `"YYYY-MM-DD"` override it for KeyMint
without writing any other property. The final value goes through the AOSP
`YYYY-MM-DD` parser and is encoded as `YYYYMM`.

#### `vendor_patchlevel`

Controls the KeyMint vendor patch level. `"auto"` first reads a nonempty runtime
`ro.vendor.build.security_patch`, then the exact key from the standard `build.prop`
locations, then falls back to the effective `os_patchlevel`. `"latest"` and an
exact `"YYYY-MM-DD"` are accepted too. The final value goes through the AOSP
`YYYY-MM-DD` parser and is encoded as `YYYYMMDD`. A nonempty source that's already
there won't be replaced by a lower-priority one just because parsing later fails.
KOBING doesn't write the vendor property.

#### `boot_patchlevel`

Controls the KeyMint boot patch level. `"auto"` first reads
`com.android.build.boot.security_patch` from the active top-level vbmeta image. If
that property is absent, KOBING looks for the same property in the active boot
image's standalone vbmeta or the vbmeta embedded in the AVB footer, then falls
back to the boot header. The legacy header field only stores a year and month, no
day, so its wire value ends in `00` — an all-zero field therefore becomes
`20000000`, but only when neither vbmeta location supplied the property. If
boot-metadata resolution fails, the fallback order is: a nonempty runtime
`ro.vendor.boot_security_patch` → the exact key from the standard `build.prop`
locations → the effective `os_patchlevel`.

`"latest"`, an exact `"YYYY-MM-DD"` date, and a decimal `u32` wire value are all
accepted. The decimal form preserves bootloader wire values like `"20000000"`
without reading them as dates. These explicit modes don't read boot metadata.
Boot patch-level resolution neither reads the system TEE nor writes the boot
property. During a hot reload, an untouched `"auto"` keeps the value that was
resolved before keymint dropped privileges; switching from an override back to
`"auto"` takes effect after keymint restarts. Explicit dates are encoded as
`YYYYMMDD`. If the chosen value can't be converted, startup fails; if a hot update
fails, the previous runtime config stays in use.

When no other `[trust]` field changes in the same save, the four patch-level
fields are resolved and applied together while keymint is running. Existing TAs
are updated in place, so in-flight operations and per-boot counters are untouched;
a representation that's effectively unchanged won't trigger an update. If the log
says the live update failed, restart keymint.

#### `vb_key`

Controls the 32-byte verified-boot public-key digest:

- `"auto"`: read `ro.boot.vbmeta.public_key_digest`, then try to compute the
  top-level vbmeta key digest, and fall back to a random value only if neither
  works;
- `"random"`: generate a new value on every keymint start; or
- a 64-character hex string: pin an exact value.

Keep `"auto"` unless you know exactly what attestation profile you're configuring.
Changing this needs a keymint restart. If `"random"` was active and you switch
back to `"auto"`, reboot the whole device so Android restores the original boot
property before `"auto"` reads it.

#### `vb_hash`

Controls the 32-byte verified-boot hash:

- `"auto"`: read `ro.boot.vbmeta.digest`, then try the original System attestation
  hash, and fall back to a random value only if neither works;
- `"random"`: generate a new value on every keymint start; or
- a 64-character hex string: pin an exact value.

The restart rule is the same as `vb_key`: restart keymint after a normal change,
and reboot the whole device when going from `"random"` back to `"auto"`.

#### `verified_boot_state`

`true` reports verified boot; `false` reports unverified. It's independent of the
`device_locked` switch. Changing it needs a keymint restart.

#### `device_locked`

`true` reports the device as locked; `false` reports it as unlocked. It doesn't
actually lock or unlock the bootloader. Changing it needs a keymint restart.

### `[device]`

When an app explicitly asks for attestation IDs, this section supplies the device
identity strings. These are personal data. Use the values the device already
generated, and restart keymint after changing this section so the one-shot
attestation-ID snapshot is rebuilt.

#### `brand`

The product brand reported in an attestation ID request, normally taken from
`ro.product.brand` when a new config is created.

#### `device`

The device code name reported in an attestation ID request, normally taken from
`ro.product.device`.

#### `product`

The product name reported in an attestation ID request, normally taken from
`ro.product.name`.

#### `manufacturer`

The manufacturer reported in an attestation ID request, normally taken from
`ro.product.manufacturer`.

#### `model`

The model reported in an attestation ID request, normally taken from
`ro.product.model`.

#### `serial`

The device serial reported in an attestation ID request, normally taken from
`ro.serialno`. Treat it as private and redact it before sharing a report.

#### `overrideTelephonyProperties`

The recommended value is `false`. Then KOBING tries to fill an empty `imei`,
`imei2`, or `meid` from the device's telephony services and property fallbacks. A
configured nonempty value is preserved, and every value KOBING discovers is
written back to the live `config.toml` when it can.

Set it to `true` and KOBING skips telephony discovery, using the three fields
exactly as written (empty strings included). Do that only when you really want to
pin the values.

#### `imei`

The primary IMEI. Leave it empty when the device has no IMEI, or when automatic
discovery should fill it. Don't make up a value just to satisfy an app.

#### `imei2`

The second IMEI. It's normal for single-SIM devices and some dual-SIM devices to
leave it empty. An empty `imei2` doesn't affect `imei` or the non-telephony
fields.

#### `meid`

The MEID, for devices that have one. Plenty of devices don't, so an empty value is
fine. An empty `meid` doesn't invalidate an available IMEI.

### `config.toml` apply summary

| Fields | What to do |
| --- | --- |
| `[main].log_level` | Restart keymint. |
| `[main].force_skip_system_biometric_hat_verification` | Applies to new checks after a valid save. |
| All `[crypto]` fields | Restart keymint; changing values can make keys unusable. |
| `[trust].security_patch`, `os_patchlevel`, `vendor_patchlevel`, `boot_patchlevel` | Hot-applied as a group when no other `[trust]` field changes; otherwise restart keymint. |
| `[trust].os_version` | Restart keymint. |
| Other `[trust]` fields | Restart keymint. |
| All `[device]` fields | Restart keymint to rebuild the cached ID snapshot. |
| `vb_key` or `vb_hash` from `"random"` to `"auto"` | Reboot the whole device. |

## `injector.toml`

### Complete annotated example

```toml
# Configuration format. Keep this at 1.
version = 1

# The package allow-list isn't here anymore. It moved to bm.txt; the path,
# format, and rules are in the bm.txt section below.

[main]
# Master switch for routing. Keep true for normal use.
enabled = true
# Injector log detail: off, error, warn, info, debug, or trace.
log_level = "debug"

[filter]
# Enforce the bm.txt allow-list and the safety rules below.
enabled = true
# Packages that must never use KOBING, even if another shared package is allowed.
deny_packages = []
# Block core Android and system identities. Keep true.
block_android_package = true
# Reject callers whose package name can't be found. Keep false.
allow_unknown_package = false

[intercept]
# Route each named KeyStore operation to KOBING for an allowed caller.
get_security_level = true
get_key_entry = true
update_subcomponent = true
list_entries = true
delete_key = true
grant = true
ungrant = true
get_number_of_entries = true
list_entries_batched = true
get_supplementary_attestation_info = true
```

### Top-level fields

#### `version`

The injector config format version — keep the integer `1`. It has nothing to do
with your Android version or the KOBING release number. A live reload with any
other value is rejected, and the last valid runtime config keeps running.

If `version` is missing at injector startup, it's treated as `0`, and `0` is
migrated in place to `1` with the rest of the file untouched. Live reload doesn't
do that migration, so such a file needs an injector restart to upgrade. A future
version that isn't recognized is never overwritten.

Any documented field you omit uses its default. Unknown fields in the documented
top-level and named sections are rejected, so don't add names this guide doesn't
mention.

#### Package allow-list

`injector.toml` doesn't store the package allow-list anymore. The exact package
names allowed to use KOBING live in `bm.txt`. See the `bm.txt` section below for
the path, format, and rules.

### `[main]`

#### `enabled`

The injector's master routing switch. When `true`, every new request goes through
the filter and the `[intercept]` settings. When `false`, nothing new is routed to
KOBING and ordinary requests stay on System. Keep it `true` for normal KOBING use.

Don't flip this while an app has a key operation open. Save the change, restart
the injector, and reopen the app when you actually want to switch routes.

#### `log_level`

Controls the injector's log. Accepted values are `"off"`, `"error"`, `"warn"`,
`"warning"`, `"info"`, `"debug"`, and `"trace"`, where `"warning"` is an alias for
`"warn"`. Matching ignores case, but lowercase is recommended. The default is
`"debug"`, which is also the usual choice for a bug report.

A valid change switches the level without restarting the injector. An unrecognized
string won't invalidate the TOML file — the injector just falls back to `debug`.

### `[filter]`

With the filter on, KOBING judges a caller in this order:

1. Reject a core Android or system identity when `block_android_package = true`.
2. If the package names can't be resolved, follow `allow_unknown_package`.
3. If any resolved package is in `deny_packages`, reject the whole identity.
4. If none of the resolved packages is listed in `bm.txt`, reject.
5. Otherwise let it through to the enabled `[intercept]` routes.

The order matters when several packages share one Android identity: a deny rule
beats a matching `bm.txt` entry.

After that normal decision, the narrow grant exception described in the `bm.txt`
section can still keep access alive for an unknown or out-of-scope app. It doesn't
override the Android-package block or `deny_packages`.

#### `enabled`

`true` enforces the `bm.txt` allow-list, the deny list, the Android-package block,
and the unknown-package policy. `false` skips all four checks and lets any caller
reach whatever is enabled under `[intercept]`.

Turning the filter off can route Android services and a pile of unrelated apps to
KOBING, which can break unlocking, app storage, or the UI. Keep it `true`.

#### `deny_packages`

An array of exact package names that must not use KOBING. Handy when a package you
picked shares its Android identity with another package that has to stay on
System. If any package resolved for the identity is denied, the whole identity is
rejected — even if another package in it is listed in `bm.txt`.

The default is an empty array, `[]`. The list uses quoted, comma-separated TOML
syntax and has nothing to do with the separate `bm.txt` allow-list.

#### `block_android_package`

When `true`, core Android and system identities are rejected before `bm.txt` even
comes into play; a resolved package name equal to `android` or starting with
`android.` is rejected too. Note this doesn't mean every ordinary app whose name
starts with `com.android.` gets blocked.

Keep it `true`. Setting it to `false` only removes this safety check; the other
filter rules still apply.

#### `allow_unknown_package`

Controls callers whose Android package name can't be resolved. `false` rejects
them, which is the safe default. `true` allows an unresolved app that didn't match
anything in `bm.txt`; core Android identities are still rejected when
`block_android_package = true`.

This isn't an "allow everything" switch. Keep it `false` unless a maintainer has
confirmed that a supported app really can't be resolved.

### `[intercept]`

Each switch maps to one Android KeyStore service operation. For a caller the
filter let through, `true` routes that operation to KOBING and `false` leaves it
on System. These switches don't migrate existing keys, and they don't make
System-created key references usable by KOBING.

The KOBING grant exception is a separate thing from ordinary package routing. A
request with a confirmed KOBING grant can return to KOBING even when the receiving
app isn't in `bm.txt`, so a granted key stays usable.

For normal use, keep them all `true`. Mixing System and KOBING operations for the
same app tends to produce missing-key errors, mismatched lists, or failed
follow-up operations.

#### `get_security_level`

Controls the request for a TEE or StrongBox security-level handle. Apps need that
handle before they can create, import, or use keys.

#### `get_key_entry`

Controls retrieval of an existing key entry, including its metadata and the handle
used for later operations.

#### `update_subcomponent`

Controls replacing an existing key entry's certificate or certificate-chain
components.

#### `list_entries`

Controls listing key aliases in the requested namespace.

#### `delete_key`

Controls deleting a named key. The selected backend is authoritative; KOBING won't
delete a matching System key to cover for it.

#### `grant`

Controls granting another app access to a key.

#### `ungrant`

Controls revoking a previously granted key permission.

#### `get_number_of_entries`

Controls counting the key entries in a namespace.

#### `list_entries_batched`

Controls paged or batched listing of key entries.

#### `get_supplementary_attestation_info`

Controls retrieving the supplementary information that supported attestation
requests need.

### Per-package subtables

Per-package tables like `[scoop.com.example.app]` and values like
`mode = "strict"` aren't supported routing options. The parser may keep them
around, but they don't change which backend handles a request. Don't add them: use
`bm.txt` for the allow-list, and `[filter]` and `[intercept]` for routing.

### `injector.toml` apply summary

Every valid change to a documented field is loaded for new requests without a
device reboot. When you change the `bm.txt` allow-list, `[main].enabled`,
`[filter]`, or `[intercept]` and want a clean boundary after the route change,
restart the injector and reopen the affected app. A syntax error, an unknown
field, or an unsupported future `version` leaves the last valid runtime config in
place; if one of those exists when the injector starts, KOBING routing stays off
until the file is fixed.

## `bm.txt`

`bm.txt` lists the exact Android package names that may use KOBING. It replaces
the old `scoop` array that used to live in `injector.toml`.

### Paths

- Runtime entity: `/data/surprise/bm.txt`

The injector reads that entity path directly.

### Format

- One package name per line, for example `com.example.app`.
- Blank lines, and lines whose first non-space character is `#`, are ignored.
- Surrounding spaces are trimmed, and duplicates collapse into one.
- App labels, partial names, and wildcards aren't supported.

At module install and on every boot, the module seeds `bm.txt` from the packaged
default list if the file is missing, then sets the owner to `keystore` and the
mode to `0644`. Editing the file takes effect for new requests without a reboot;
if you want a clean route boundary, restart the injector and reopen the affected
app.

### Default contents

```text
io.github.vvb2060.keyattestation
com.google.android.gsf
com.google.android.gms
com.android.vending
com.eltavine.duckdetector
```

Android can hand several packages the same identity. When it does, listing any
one of them allows the whole identity, unless a filter rule rejects one of the
packages in the group. Adding or removing a package doesn't move or convert keys
between System and KOBING; an app may end up unable to open keys it created
through the other route.

There's also one narrow granted-key exception. An app outside `bm.txt`, or one
whose package name can't be resolved, can still use KOBING to confirm access to a
KOBING key. That keeps a key deliberately shared by another app usable, without
handing the receiving app general KOBING access. Callers that Android blocks, or
that the deny list names, don't get this exception.
