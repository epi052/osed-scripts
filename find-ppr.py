import argparse
from enum import auto
from enum import Enum

import pykd

# Example bad chars, change to whatever
BADCHARS = [0x00, 0x0A, 0x0D]
# BADCHARS = [0x00,0x02,0x03,0x09,0x0A,0x0D,0x20,0x2E,0x2F]


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


def checkBadChars(bAddr):
    for i in bAddr:
        if i in BADCHARS:
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
        for i in BADCHARS:
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
                        bcChk = checkBadChars(bAddr)
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
        totalGadgets = (totalGadgets + numGadgets
                        )  # Increment total number of gadgets found
    print("\n---- STATS ----")  # Print out all the stats
    print(">> BADCHARS: ", end="")
    for i in BADCHARS:
        print("\\x{:02X}".format(i), end="")
    print()
    print(f">> Usable Gadgets Found: {totalGadgets}")
    print(">> Module Gadget Counts")
    for m, c in modGadgetCount.items():
        print("   - {}: {} ".format(m, c))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s",
                        dest="showbc",
                        help="Show addresses with bad chars",
                        action="store_true")
    parser.add_argument(
        "modules",
        help=
        "module name(s) to search for pop pop ret (ex: find-ppr.py libspp diskpls libpal)",
        nargs="+",
    )
    args = parser.parse_args()
    main(args)
    print("Done!")
