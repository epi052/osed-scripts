#!/bin/bash

TOOLS=("https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip" "https://github.com/corelan/windbglib/raw/master/windbglib.py" "https://github.com/corelan/mona/raw/master/mona.py" "https://www.python.org/ftp/python/2.7.17/python-2.7.17.msi" "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe" "https://raw.githubusercontent.com/epi052/osed-scripts/main/install-mona.ps1")

TMPDIR=$(mktemp -d)
SHARENAME="mona-share"
SHARE="\\\\tsclient\\$SHARENAME"

trap "rm -rf $TMPDIR" SIGINT 

pushd $TMPDIR >/dev/null

echo "[+] once the RDP window opens, execute the following command in an Administrator terminal:"
echo
echo "powershell -c \"cat $SHARE\\install-mona.ps1 | powershell -\""
echo

for tool in "${TOOLS[@]}"; do
    echo "[=] downloading $tool"
    wget -q "$tool"
done

unzip -qqo pykd.zip

rdesktop ${1} -u offsec -p lab -r disk:$SHARENAME=.

