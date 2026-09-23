# shellcheck disable=SC2034
SKIPUNZIP=1

SONAME="Ko Bing"
SUPPORTED_ABIS="arm64 x64"
MIN_SDK=29

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if [ "$(which magisk)" ]; then
    ui_print "*********************************************************"
    ui_print "! Multiple root implementation is NOT supported!"
    ui_print "! Please uninstall Magisk before installing Ko Bing"
    abort    "*********************************************************"
  fi
elif [ "$BOOTMODE" ] && [ "$MAGISK_VER_CODE" ]; then
  ui_print "- Installing from Magisk app"
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from KernelSU or Magisk app"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing $SONAME $VERSION"

# check architecture
support=false
for abi in $SUPPORTED_ABIS
do
  if [ "$ARCH" == "$abi" ]; then
    support=true
  fi
done
if [ "$support" == "false" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

# check android
if [ "$API" -lt $MIN_SDK ]; then
  ui_print "! Unsupported sdk: $API"
  abort "! Minimal supported sdk is $MIN_SDK"
else
  ui_print "- Device sdk: $API"
fi

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "*********************************************************"
fi
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" 'customize.sh'  "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh'     "$TMPDIR/.vunzip"

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'     "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'service.sh'      "$MODPATH"
extract "$ZIPFILE" 'sepolicy.rule'   "$MODPATH"
extract "$ZIPFILE" 'daemon'          "$MODPATH"
extract "$ZIPFILE" 'daemon-injector' "$MODPATH"
extract "$ZIPFILE" 'injector.toml'   "$MODPATH"
extract "$ZIPFILE" 'keybox.xml'      "$MODPATH"
extract "$ZIPFILE" 'bm.txt'          "$MODPATH"
extract "$ZIPFILE" 'webroot/index.html' "$MODPATH"
chmod 755 "$MODPATH/daemon" "$MODPATH/daemon-injector" \
  "$MODPATH/post-fs-data.sh" "$MODPATH/service.sh"


if [ "$ARCH" = "x64" ] || [ "$ARCH" = "x86_64" ]; then
  ui_print "- Using packaged x64 binaries"
  BINDIR="$MODPATH/libs/x86_64"
  extract "$ZIPFILE" 'libs/x86_64/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/inject'  "$MODPATH"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "arm64-v8a" ]; then
  ui_print "- Using packaged arm64 binaries"
  BINDIR="$MODPATH/libs/arm64-v8a"
  extract "$ZIPFILE" 'libs/arm64-v8a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/inject'  "$MODPATH"
else
  abort "! Unsupported platform: $ARCH"
fi

[ -f "$BINDIR/keymint" ] || abort "! Missing $BINDIR/keymint"
[ -f "$BINDIR/inject" ] || abort "! Missing $BINDIR/inject"
chmod 755 "$BINDIR/keymint" "$BINDIR/inject"

BASE_DIR=/data/surprise
WASTE_DIR=$BASE_DIR/waste
STATE_DIR=$WASTE_DIR
OLD_KS_DIR=/data/misc/keystore/ko_bing
OLD_ADB_DIR=/data/adb/ko_bing

mkdir -p "$BASE_DIR" "$WASTE_DIR"
# Lock down the top-level directory. NOTE: mode 0600 on a directory removes the
# execute bit, so nothing (not even the module) can traverse into it; see the
# module README for the trade-off.
chmod 0600 "$BASE_DIR"

# One-time migration from the legacy split layout. Best effort only: never
# overwrite a file that already exists at the new location.
[ -f "$OLD_KS_DIR/keybox.xml" ]    && [ ! -f "$BASE_DIR/keybox.xml" ]    && cp -a "$OLD_KS_DIR/keybox.xml"    "$BASE_DIR/keybox.xml"
[ -f "$OLD_KS_DIR/injector.toml" ] && [ ! -f "$BASE_DIR/injector.toml" ] && cp -a "$OLD_KS_DIR/injector.toml" "$BASE_DIR/injector.toml"
for entry in data logs config.toml config.toml.bak config.toml.bak2 crash_count; do
  if [ -e "$OLD_KS_DIR/$entry" ] && [ ! -e "$WASTE_DIR/$entry" ]; then
    cp -a "$OLD_KS_DIR/$entry" "$WASTE_DIR/$entry"
  fi
done

rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all"
rm -f "$STATE_DIR/keymint" "$STATE_DIR/inject" "$STATE_DIR/injector" # clean up old hot-update binaries

# Seed the package allow-list directly into /data/surprise: migrate any legacy
# entity first, then fall back to the packaged default.
BM_FILE=$BASE_DIR/bm.txt
if [ ! -f "$BM_FILE" ]; then
  for src in "$OLD_ADB_DIR/kobing_bm.txt" "$OLD_ADB_DIR/bm.txt" "$BASE_DIR/kobing_bm.txt" "$MODPATH/bm.txt"; do
    if [ -f "$src" ]; then
      cp -a "$src" "$BM_FILE"
      break
    fi
  done
fi

# Clean up the legacy /data/adb/ko_bing layout only after migration is done.
rm -rf "$OLD_ADB_DIR"

if [ -f "$BM_FILE" ]; then
  chmod 0644 "$BM_FILE"
fi