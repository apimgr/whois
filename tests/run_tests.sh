#!/usr/bin/env bash
# shellcheck shell=bash
# - - - - - - - - - - - - - - - - - - - - - - - - -
##@Version           :  202611231958-git
# @@Author           :  Jason Hempstead
# @@Contact          :  git-admin@casjaysdev.pro
# @@License          :  WTFPL
# @@ReadME           :  README.md
# @@Copyright        :  Copyright: (c) 2026 Jason Hempstead, Casjays Developments
# @@Created          :  Monday, November 23, 2026 19:58 EST
# @@File             :  run_tests.sh
# @@Description      :  Run the basic Docker integration test tier.
# @@Changelog        :  Run only the Docker basic tier; keep full suites explicit.
# @@TODO             :  None
# @@Other            :  Full-app and browser suites are explicit.
# @@Resource         :  AI.md PART 28
# @@Terminal App     :  yes
# @@sudo/root        :  no
# @@Template         :  shell/bash
# - - - - - - - - - - - - - - - - - - - - - - - - -
# shellcheck disable=SC1001,SC1003,SC2001,SC2003,SC2016,SC2031,SC2090,SC2115,SC2120,SC2155,SC2199,SC2229,SC2317,SC2329
# - - - - - - - - - - - - - - - - - - - - - - - - -

set -eo pipefail

APPNAME="${0##*/}"
VERSION="202611231958-git"
RUN_USER="${USER:-$(id -un)}"
SET_UID="${UID:-$(id -u)}"
SCRIPT_SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

echo "$APPNAME $VERSION: running basic tests as $RUN_USER (uid $SET_UID)"

if command -v docker &>/dev/null; then
  echo "Docker detected - running the basic tests..."
  exec "$SCRIPT_SRC_DIR/docker.sh"
fi

echo "ERROR: docker not found: every test script builds with Docker" >&2
echo "Install Docker: https://docker.com/" >&2
exit 69

# ex: ts=2 sw=2 et filetype=sh
