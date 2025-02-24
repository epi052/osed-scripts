#!/bin/bash

# Function to display usage information
function display_help {
    echo "Usage: install-pykd-py3.sh <RDP_IP_Addr> <username> <password>"
    echo "Options:"
    echo "  -h  Display this help message"
}

TOOLS=(
    # From: https://github.com/ivellioscolin/pykd-ext/releases
    "https://github.com/user-attachments/files/18549260/pykd_ext_2.0.0.25_x86.zip"
    # From: https://pypi.org/project/pykd/#files
    ## 3.9 x86
    "https://files.pythonhosted.org/packages/67/f7/19b2380834b6b4312a89731b0f00c8185b7f1ac015f2947da2969de5b37d/pykd-0.3.4.15-cp39-none-win32.whl"
    ## 3.8 x86
    "https://files.pythonhosted.org/packages/f3/41/54f0561d2e431315b31a11b140953439e46ee6cfd0f944fc5600a2c90b84/pykd-0.3.4.15-cp38-none-win32.whl"
)

echo "[*] Script for installing pykd for python3.9 & 3.8"
echo "Respect and original idea: epi052"

# Check if no arguments provided or -h flag is used
if [ $# -eq 0 ] || [ "$1" == "-h" ]; then
    display_help
    exit 0
fi

TMPDIR=$(mktemp -d)
SHARENAME="pykd_share"
SHARE="\\\\tsclient\\$SHARENAME"
SCRIPT_NAME="install-pykd-py3.ps1"

echo "[+] Created temp directory: $TMPDIR"
echo "[+] Copy $SCRIPT_NAME to $TMPDIR"
cp ./$SCRIPT_NAME $TMPDIR
trap "rm -rf $TMPDIR" SIGINT

pushd $TMPDIR >/dev/null

echo "[+] once the RDP window opens, execute the following command in an Administrator terminal:"
echo
echo "powershell -c \"cat $SHARE\\$SCRIPT_NAME | powershell -\""
echo

for tool in "${TOOLS[@]}"; do
    echo "[=] downloading $tool"
    wget -q "$tool"
done

unzip -qqo *.zip

# 1: IP address, 2: username, 3: password
rdesktop ${1} -u ${2} -p ${3} -r disk:$SHARENAME=.
