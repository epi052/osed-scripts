import pykd
import argparse
from enum import Enum, auto


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


class Module:
    # 00400000 00465000   diskpls    (deferred)
    def __init__(self, unparsed):
        self.name = "unknown"
        self.start = -1
        self.end = -1
        self.unparsed = unparsed.split()
        self.parse()

    def parse(self):
        if len(self.unparsed) >= 3:
            self.start = self.unparsed[0]
            self.end = self.unparsed[1]
            self.name = self.unparsed[2]

    def __str__(self):
        return f"{self.name}(start={self.start}, end={self.end})"


class PopR32(Enum):
    eax = 0x58
    ecx = auto()
    edx = auto()
    ebx = auto()
    esp = auto()
    esi = auto()
    edi = auto()


def checkBadChars(bAddr, badChars):
    for i in bAddr:
        if i in badChars:
            return "--"
    return "OK"


def main(args):
    modules = pykd.dbgCommand("lm")
    totalGadgets = 0  # This tracks all the total number of usable gadgets
    modGadgetCount = {}  # This tracks the number of gadgets per module
    for mod_line in modules.splitlines():
        module = Module(mod_line)

        if module.name.lower() not in [mod.lower() for mod in args.modules]:
            continue
        numGadgets = 0  # This is the number of gadgets found in this module
        print(f"[+] searching {module.name} for pop r32; pop r32; ret")
        print("[+] BADCHARS: ", end="")
        for i in args.bad:
            print("\\x{:02X}".format(i), end="")
        print()

        for pop1 in range(0x58, 0x60):

            for pop2 in range(0x58, 0x60):
                command = (
                    f"s-[1]b {module.start} {module.end} {hex(pop1)} {hex(pop2)} c3"
                )
                result = pykd.dbgCommand(command)

                if result is None:
                    continue

                for addr in result.splitlines():
                    try:
                        bAddr = int(addr, 16).to_bytes(4, "little")
                        bcChk = checkBadChars(bAddr, args.bad)
                        bAddrEsc = ""  # This is the escaped string containing the little endian addr for shellcode output
                        for b in bAddr:
                            bAddrEsc += "\\x{:02X}".format(b)
                        if args.showbc and bcChk == "--":
                            print(
                                f"[{bcChk}] {module.name}::{addr}: pop {PopR32(pop1).name}; pop {PopR32(pop2).name}; ret ; {bAddrEsc}"
                            )
                        elif bcChk == "OK":
                            print(
                                f"[{bcChk}] {module.name}::{addr}: pop {PopR32(pop1).name}; pop {PopR32(pop2).name}; ret ; {bAddrEsc}"
                            )
                            numGadgets = numGadgets + 1
                    except ValueError:
                        # not a valid pop r32
                        pass
        print(f"[+] {module.name}: Found {numGadgets} usable gadgets!")
        modGadgetCount[module.name] = numGadgets  # Add to the dict
        totalGadgets = (
            totalGadgets + numGadgets
        )  # Increment total number of gadgets found
    print("\n---- STATS ----")  # Print out all the stats
    print(">> BADCHARS: ", end="")
    for i in args.bad:
        print("\\x{:02X}".format(i), end="")
    print()
    print(f">> Usable Gadgets Found: {totalGadgets}")
    print(">> Module Gadget Counts")
    for m, c in modGadgetCount.items():
        print("   - {}: {} ".format(m, c))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--showbc",
        help="Show addresses with bad chars",
        action="store_true"
    )
    parser.add_argument(
        "-b",
        "--bad",
        help="space separated list of hex bytes that are already known bad (ex: -b 00 0a 0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    parser.add_argument(
        "-m",
        "--modules",
        help="module name(s) to search for pop pop ret (ex: find-ppr.py libspp diskpls libpal)",
        required=True,
        nargs="+",
    )
    args = parser.parse_args()
    main(args)
    print("Done!")