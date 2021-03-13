$share_path = "\\tsclient\mona-share\"
$insall_dir = "C:\Users\Offsec\Desktop\install-monas"

mkdir $insall_dir

# move Offsec's pykd files out of the way
move "C:\Program Files\Windows Kits\10\Debuggers\x86\winext\pykd.pyd" "C:\Program Files\Windows Kits\10\Debuggers\x86\winext\pykd.pyd.bak"
move "C:\Program Files\Windows Kits\10\Debuggers\x86\winext\pykd.dll" "C:\Program Files\Windows Kits\10\Debuggers\x86\winext\pykd.dll.bak"

# install python2.7
copy "$share_path\python-2.7.17.msi" $insall_dir
msiexec.exe /i $insall_dir\python-2.7.17.msi /qn
start-sleep 10

# register Python2.7 binaries in path before Python3
$p = [System.Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable('Path',"C:\Python27\;C:\Python27\Scripts;"+$p,[System.EnvironmentVariableTarget]::User)


# install old c++ runtime
copy "$share_path\vcredist_x86.exe" $insall_dir
$insall_dir\vcredist_x86.exe /Q
start-sleep 10

# register runtime debug dll
cd "C:\Program Files\Common Files\Microsoft Shared\VC"
regsvr32 /s msdia90.dll

# copy mona files
copy "$share_path\windbglib.py" "C:\Program Files\Windows Kits\10\Debuggers\x86"
copy "$share_path\mona.py" "C:\Program Files\Windows Kits\10\Debuggers\x86"
copy "$share_path\pykd.pyd" "C:\Program Files\Windows Kits\10\Debuggers\x86\winext"
