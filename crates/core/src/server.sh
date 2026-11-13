#!/bin/sh
# Vigil's server inventory, sent on ssh's stdin and run by `sh -s`. The app puts two
# lines before it: `marker=<random hex>` and `set -- '<folder>' ...` with the folders whose
# lockfiles are read. Neither is on the remote command line, so other users of the server cannot
# see the marker in `ps`.
#
# It only reads: it never uses sudo, and writes no file. Its one connection is `docker`'s to the
# daemon the server's docker is set up for (DOCKER_HOST or the current context), which may be
# on another host. It is not pinned to /var/run/docker.sock, since rootless docker listens
# elsewhere, and `ps` and `images` only read.
#
# Each part of the answer is printed as a "<marker> begin <part>" line, the part's output, an
# empty line and a "<marker> end <exit status>" line. The marker is random per run, so no file's
# content can end a part early. Standard error is dropped for the whole script: the exit status
# says whether a part was read, and error text from the server would only reach the user's
# terminal.

# shellcheck disable=SC2154 # marker is set by the app's first line
exec 2>/dev/null
nl='
'

part() {
  name=$1
  shift
  printf '%s begin %s\n' "$marker" "$name"
  "$@" </dev/null
  status=$?
  printf '\n%s end %s\n' "$marker" "$status"
}

# shellcheck disable=SC2329 # called through part
os_release() {
  cat /etc/os-release || cat /usr/lib/os-release
}

# shellcheck disable=SC2329 # called through part
listening() {
  ss -tulpn || netstat -tulpn
}

# The lockfile names and skipped folders match the Mac's project folder walk (lockfiles.rs).
# Names with a newline are skipped, since the list is one path per line. The exit status is
# find's own: not 0 when some folder below could not be read. `-H` follows the folder itself
# when it is a symlink (a deploy's `current` link), as the `[ -d ]` check before it does;
# without it find lists nothing under such a folder. Symlinks below it are still not followed.
lockfiles() {
  find -H "$1" -mindepth 1 \
    \( -name "*$nl*" -o -type d \( -name '.*' -o -name node_modules -o -name target \
    -o -name vendor -o -name dist -o -name build \) \) -prune \
    -o -type f \( -name Cargo.lock -o -name package-lock.json -o -name npm-shrinkwrap.json \
    -o -name uv.lock -o -name poetry.lock \) -print
}

# Prints one lockfile. Exit status 3: 16 MiB or larger; 4: it would take the files read past
# 128 MiB in all, which leaves room under the app's 256 MiB limit for the other parts. The type
# is checked again, since the file may have been replaced by a symlink or a FIFO since the
# listing (a FIFO would block); a swap in the moment between this check and the read is not
# caught.
# shellcheck disable=SC2329 # called through part
lockfile() {
  { [ -f "$1" ] && [ ! -L "$1" ]; } || return 1
  size=$(wc -c <"$1") || return 1
  [ "$size" -lt 16777216 ] || return 3
  [ $((total + size)) -le 134217728 ] || return 4
  total=$((total + size))
  cat -- "$1"
}

part os-release os_release
part kernel uname -srm
part dpkg cat /var/lib/dpkg/status
part apk cat /lib/apk/db/installed
part rpm rpm -qa
part listening listening
part docker-containers docker ps --no-trunc --format '{{json .}}'
part docker-images docker images --digests --no-trunc --format '{{json .}}'

# Each folder's part lists every lockfile found, with status 100 when the folder is not a
# folder (gone) and 101 when this login may not read it; at most 200 of them are read. The
# loop splits the list on newlines only and with globbing off, in this shell, so `total`
# carries across folders.
total=0
for dir in "$@"; do
  if [ ! -d "$dir" ]; then
    files=
    status=100
  elif [ ! -r "$dir" ]; then
    files=
    status=101
  else
    files=$(lockfiles "$dir")
    status=$?
  fi
  printf '%s begin dir %s\n%s\n%s end %s\n' "$marker" "$dir" "$files" "$marker" "$status"
  set -f
  IFS=$nl
  count=0
  for file in $files; do
    count=$((count + 1))
    [ "$count" -le 200 ] || break
    part "file $file" lockfile "$file"
  done
  unset IFS
  set +f
done
exit 0
