MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/ko_bing
LOG_DIR=$TARGET_DIR/logs
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
STATE_DIR=/data/adb/ko_bing


mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"

mkdir -p "$LOG_DIR"
chmod 0770 "$LOG_DIR"
chown 1017:1017 "$LOG_DIR"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/keymint.pid" "$STATE_DIR/injector.pid"
rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all"

# Package allow-list (bm.txt). The real file lives in /data/surprise so that the
# keystore user can read it; /data/adb/ko_bing/kobing_bm.txt is only a symlink for the
# user to edit conveniently with a root file manager.
BM_DIR=/data/surprise
BM_FILE=$BM_DIR/kobing_bm.txt
BM_LINK=$STATE_DIR/kobing_bm.txt
mkdir -p "$BM_DIR"
if [ ! -f "$BM_FILE" ] && [ -f "$MODDIR/bm.txt" ]; then
  cp "$MODDIR/bm.txt" "$BM_FILE"
fi
if [ -f "$BM_FILE" ]; then
  chmod 0644 "$BM_FILE"
  if [ ! -L "$BM_LINK" ] || [ "$(readlink "$BM_LINK" 2>/dev/null)" != "$BM_FILE" ]; then
    rm -f "$BM_LINK"
    ln -s "$BM_FILE" "$BM_LINK"
  fi
fi

if [ ! -f "$TARGET_KEYBOX" ] && [ -f "$MODDIR/keybox.xml" ]; then
  cp "$MODDIR/keybox.xml" "$TARGET_KEYBOX"
fi

if [ ! -f "$TARGET_INJECTOR_CONFIG" ] && [ -f "$MODDIR/injector.toml" ]; then
  cp "$MODDIR/injector.toml" "$TARGET_INJECTOR_CONFIG"
fi

if [ -f "$TARGET_KEYBOX" ]; then
  chmod 0600 "$TARGET_KEYBOX"
  chown 1017:1017 "$TARGET_KEYBOX"
fi

if [ -f "$TARGET_INJECTOR_CONFIG" ]; then
  chmod 0600 "$TARGET_INJECTOR_CONFIG"
  chown 1017:1017 "$TARGET_INJECTOR_CONFIG"
fi
