#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/.."

/usr/local/bin/pip3 freeze | xargs /usr/local/bin/pip3 uninstall -y
/usr/local/bin/pip3 install -r requirements.txt
/usr/local/bin/pip3 install pyinstaller