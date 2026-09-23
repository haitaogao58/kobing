MODDIR=${0%/*}
BASE_DIR=/data/surprise
WASTE_DIR=$BASE_DIR/waste
LOG_DIR=$WASTE_DIR/logs
TARGET_KEYBOX=$BASE_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$BASE_DIR/injector.toml
STATE_DIR=$WASTE_DIR

mkdir -p "$BASE_DIR"

mkdir -p "$WASTE_DIR"
chmod 0770 "$WASTE_DIR"
chown 1017:1017 "$WASTE_DIR"

mkdir -p "$LOG_DIR"
chmod 0770 "$LOG_DIR"
chown 1017:1017 "$LOG_DIR"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/keymint.pid" "$STATE_DIR/injector.pid"
rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all"

# Package allow-list (bm.txt). It lives directly in /data/surprise so that the
# keystore user can read it and the user can edit it with a root file manager.
BM_FILE=$BASE_DIR/bm.txt
if [ ! -f "$BM_FILE" ]; then
  for src in "$BASE_DIR/kobing_bm.txt" "$MODDIR/bm.txt"; do
    if [ -f "$src" ]; then
      cp -a "$src" "$BM_FILE"
      break
    fi
  done
fi
if [ -f "$BM_FILE" ]; then
  chmod 0644 "$BM_FILE"
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