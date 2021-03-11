# osed-scripts
bespoke tooling for offensive security's Windows Usermode Exploit Dev course (OSED)

## Requirements:
all scripts require `pykd`

run `.load pykd` then `!py c:\path\to\this\repo\script.py` 

## find-ppr.py

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
