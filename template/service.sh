MODDIR=${0%/*}
STATE_DIR=/data/surprise/waste

mkdir -p "$STATE_DIR"

pid_matches_script() {
  pid=$1
  script=$2
  [ -r "/proc/$pid/cmdline" ] || return 1
  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  echo "$cmdline" | grep -F "$script" >/dev/null 2>&1
}

start_daemon() {
  script=$1
  pidfile=$2

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi

  sh "$script" &
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

start_daemon "$MODDIR/daemon" "$STATE_DIR/keymint.pid"
start_daemon "$MODDIR/daemon-injector" "$STATE_DIR/injector.pid"

# Generate the WebUI application-name table consumed by the app selector.
# Rendered as webroot/apps_data.js (window.KB_APPS) so the browser picks it up
# through the existing <script src="apps_data.js"> tag. Runs in the background
# and is skipped entirely when the helper is unavailable, in which case the
# WebUI falls back to its own runtime generation.
generate_apps_data() {
  [ -x "$MODDIR/tools/applist.sh" ] || return 0
  web="$MODDIR/webroot"
  [ -d "$web" ] || return 0
  # Wait until the package manager is actually ready. Running this too early
  # in boot yields a table that only contains the bm.txt entries (pm/aapt not
  # yet available), which must not happen because the table is meant to hold
  # the full installed-app list with real labels.
  i=0
  while [ "$i" -lt 90 ]; do
    if [ -n "$(pm list packages 2>/dev/null)" ]; then
      break
    fi
    i=$((i+1))
    sleep 2
  done
  tmp="$web/.apps_data.$$"
  if sh "$MODDIR/tools/applist.sh" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    { printf 'window.KB_APPS = '; cat "$tmp"; printf ';\n'; } > "$web/apps_data.js"
    chmod 0644 "$web/apps_data.js"
  fi
  rm -f "$tmp"
}
generate_apps_data &
