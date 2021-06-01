import pykd
import argparse


def hex_byte(byte_str):
    """validate user input is a hex representation of an int between 0 and 255 inclusive"""
    if byte_str == "??":
        # windbg shows ?? when it can't access a memory region, but we shouldn't stop execution because of it
        return byte_str

    try:
        val = int(byte_str, 16)
        if 0 <= val <= 255:
            return val
        else:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"only *hex* bytes between 00 and ff are valid, found {byte_str}"
        )


class Memdump:
    def __init__(self, line):
        self.__bytes = list()
        self.__address = ""
        self._parse_line(line)

    @property
    def bytes(self):
        return self.__bytes

    @bytes.setter
    def bytes(self, val: str):
        self.__bytes = [hex_byte(x) for x in val.split()]

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, val: str):
        self.__address = val

    def _parse_line(self, line):
        # 0185ff54  99 77 9e 77 77 c9 03 8c-60 77 9e 77 60 77 9e 77  .wžwwÉ.Œ`wžw`wžw
        # double space as delim will give 0 as the address and 1 as the bytes, the rest can be discarded
        parts = line.split("  ")[:2]  # discard the ascii portion right away

        if len(parts) == 0:
            return

        self.address = parts[0]
        bytes_str = ""

        for i, byte in enumerate(parts[1].split()):
            if i == 7:
                # handle the hyphen separator between the 8th and 9th byte
                # 99 77 9e 77 77 c9 03 8c-60 77 9e 77 60 77 9e 77
                bytes_str += " ".join(byte.split("-")) + " "
                continue
            bytes_str += f"{byte} "

        # pass to the setter as a space separated string of hex bytes for further processing/assignment
        self.bytes = bytes_str

    def __str__(self):
        byte_str = ""
        for byte in self.bytes:
            if byte == "??":
                byte_str += f"{byte} "
            else:
                byte_str += f"{byte:02X} "

        return f"{self.address}  {byte_str}"


def find_bad_chars(args):
    chars = bytes(i for i in range(args.start, args.end + 1) if i not in args.bad)

    command = f"db {args.address} L 0n{len(chars)}"
    result = pykd.dbgCommand(command)

    if result is None:
        print(f"[!] Ran '{command}', but received no output; exiting...")
        raise SystemExit

    char_counter = 0

    for line in result.splitlines():
        memdump = Memdump(line)
        print(memdump)
        print(" " * 10, end="")  # filler for our comparison line

        for byte in memdump.bytes:
            if byte == chars[char_counter]:
                print(f"{byte:02X}", end=" ")
            else:
                print("--", end=" ")

            char_counter += 1

        print()


def generate_byte_string(args):
    known_bad = ", ".join(f'{x:02X}' for x in args.bad)
    var_str = f"chars = bytes(i for i in range({args.start}, {args.end + 1}) if i not in [{known_bad}])"

    print("[+] characters as a range of bytes")
    print(var_str, end="\n\n")

    print("[+] characters as a byte string")

    # deliberately not using enumerate since it may not execute in certain situations depending on user input for the
    # range bounds
    counter = 0

    for i in range(args.start, args.end + 1):
        if i in args.bad:
            continue

        if i == args.start:
            # first byte
            print(f"chars  = b'\\x{i:02X}", end="")
        elif counter % 16 == 0:
            # start a new line
            print("'")
            print(f"chars += b'\\x{i:02X}", end="")
        else:
            print(f"\\x{i:02X}", end="")

        counter += 1

    if counter % 16 != 0 and counter != 0:
        print("'")


def main(args):
    if args.address is not None:
        find_bad_chars(args)
    else:
        generate_byte_string(args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-s",
        "--start",
        help="hex byte from which to start searching in memory (default: 00)",
        default=0,
        type=hex_byte,
    )
    parser.add_argument(
        "-e",
        "--end",
        help="last hex byte to search for in memory (default: ff)",
        default=255,
        type=hex_byte,
    )
    parser.add_argument(
        "-b",
        "--bad",
        help="space separated list of hex bytes that are already known bad (ex: -b 00 0a 0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )

    mutuals = parser.add_mutually_exclusive_group(required=True)
    mutuals.add_argument(
        "-a", "--address", help="address from which to begin character comparison"
    )
    mutuals.add_argument(
        "-g",
        "--generate",
        help="generate a byte string suitable for use in source code",
        action="store_true",
    )

    parsed = parser.parse_args()

    if parsed.start > parsed.end:
        print("[!] --start value must be higher than --end; exiting...")
        raise SystemExit

    main(parsed)
