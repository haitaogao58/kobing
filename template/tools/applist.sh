#!/system/bin/sh
# KoBing WebUI application-name table generator.
#
# Emits a single-line JSON object on stdout:
#   {"com.example.app":{"l":"Example App"}, ...}
#
# Consumed in two ways:
#   1) service.sh renders it into webroot/apps_data.js as:
#          window.KB_APPS = { ... };
#   2) the WebUI may call this script through the KernelSU bridge when
#      apps_data.js is missing or stale (it JSON.parses the stdout).
#
# The display label is read from the packaged AOSP `aapt` (see tools/aapt).
# If aapt is unavailable or the APK cannot be parsed, the package name itself
# is used as the label so the entry is never dropped.

MODDIR=${0%/*}
AAPT="$MODDIR/aapt"
[ -x "$AAPT" ] || AAPT=aapt
BM_FILE=/data/surprise/bm.txt

WORK="${TMPDIR:-/data/local/tmp}/kobing_applist.$$"
mkdir -p "$WORK" 2>/dev/null || WORK="/tmp/kobing_applist.$$"
mkdir -p "$WORK" 2>/dev/null
ROWS="$WORK/rows"
: > "$ROWS"

# Escape a raw label so it is safe inside a JSON/JS double-quoted string and
# collapse newlines (labels never legitimately contain them).
json_escape() {
  printf '%s' "$1" | tr -d '\r\n' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

label_for() {
  pkg="$1"
  apk=$(pm path "$pkg" 2>/dev/null | head -n1 | cut -d: -f2)
  if [ -z "$apk" ]; then
    printf '%s' "$pkg"
    return 0
  fi
  lbl=$("$AAPT" dump badging "$apk" 2>/dev/null | sed -n "s/^application-label:'\(.*\)'$/\1/p" | head -n1)
  [ -z "$lbl" ] && lbl="$pkg"
  printf '%s' "$lbl"
}

# Candidate packages: every third-party app plus anything pinned in bm.txt
# (which may reference system apps that -3 does not list).
list_pkgs() {
  pm list packages -3 2>/dev/null | cut -d: -f2
  if [ -f "$BM_FILE" ]; then
    tr -d '\r' < "$BM_FILE" \
      | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//' \
      | grep -v '^$'
  fi
}

list_pkgs | sort -u | while IFS= read -r pkg; do
  [ -z "$pkg" ] && continue
  printf '%s\n%s\n' "$pkg" "$(json_escape "$(label_for "$pkg")")"
done > "$ROWS"

printf '{'
first=1
while IFS= read -r pkg; do
  IFS= read -r lbl
  [ -z "$pkg" ] && continue
  if [ "$first" = "1" ]; then first=0; else printf ','; fi
  printf '"%s":{"l":"%s"}' "$pkg" "$lbl"
done < "$ROWS"
printf '}\n'

rm -rf "$WORK"