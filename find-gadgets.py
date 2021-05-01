#!/usr/bin/env python3
import sys
import argparse
from rich import print
from rich.tree import Tree
from ropper import RopperService


class Gadgetizer:
    def __init__(self, files, badbytes, output):
        self.files = files
        self.output = output
        self.badbytes = "".join(
            badbytes
        )  # ropper's badbytes option has to be an instance of str
        self.ropper_svc = self.get_ropper_service()

    def get_ropper_service(self):
        # not all options need to be given
        options = {
            "color": True,
            "badbytes": self.badbytes,
            "type": "rop",
        }  # if gadgets are printed, use detailed output; default: False

        rs = RopperService(options)

        for file in self.files:
            if ":" in file:
                file, base = file.split(":")
                rs.addFile(file, arch="x86")
                rs.clearCache()
                rs.setImageBaseFor(name=file, imagebase=int(base, 16))
            else:
                rs.addFile(file, arch="x86")
                rs.clearCache()

            rs.loadGadgetsFor(file)

        return rs

    def get_gadgets(self, search_str, quality=1, strict=False):
        gadgets = [
            (f, g)
            for f, g in self.ropper_svc.search(search=search_str, quality=quality)
        ]  # could be memory hog

        if not gadgets and quality < self.ropper_svc.options.inst_count and not strict:
            # attempt highest quality gadget, continue requesting with lower quality until something is returned
            return self.get_gadgets(search_str, quality=quality + 1)

        return gadgets

    def _search_gadget(self, title, search_strs):
        title = f"[bright_yellow]{title}[/bright_yellow] gadgets"
        tree = Tree(title)

        for search_str in search_strs:
            for file, gadget in self.get_gadgets(search_str):
                tree.add(f"{gadget} :: {file}")

        return tree

    def add_gadgets_to_tree(self, tree):
        zeroize_strs = []
        eip_to_esp_strs = ["jmp esp;", "leave;", "mov esp, ???;", "call esp;"]

        tree.add(self._search_gadget("write-what-where", ["mov [???], ???;"]))
        tree.add(self._search_gadget("pointer deref", ["mov ???, [???];"]))
        tree.add(
            self._search_gadget(
                "swap register",
                ["mov ???, ???;", "xchg ???, ???;", "push ???; pop ???;"],
            )
        )
        tree.add(self._search_gadget("increment register", ["inc ???;"]))
        tree.add(self._search_gadget("decrement register", ["dec ???;"]))
        tree.add(self._search_gadget("add register", ["add ???, e??;"]))
        tree.add(self._search_gadget("subtract register", ["sub ???, e??;"]))
        tree.add(self._search_gadget("negate register", ["neg e??;"]))
        tree.add(self._search_gadget("push", ["push e??;"]))
        tree.add(self._search_gadget("pop", ["pop e??;"]))
        tree.add(self._search_gadget("push-pop", ["sub eax, ecx;"]))

        for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi"]:
            zeroize_strs.append(f"xor {reg}, {reg};")
            zeroize_strs.append(f"sub {reg}, {reg};")
            zeroize_strs.append(f"lea [{reg}], 0;")
            zeroize_strs.append(f"mov {reg}, 0;")
            zeroize_strs.append(f"and {reg}, 0;")
            eip_to_esp_strs.append(f"xchg esp, {reg}; jmp {reg};")
            eip_to_esp_strs.append(f"xchg esp, {reg}; call {reg};")

        tree.add(self._search_gadget("zeroize", zeroize_strs))
        tree.add(self._search_gadget("eip to esp", eip_to_esp_strs))

    def save(self):
        self.ropper_svc.options.color = False

        with open(self.output, "w") as f:
            for file in self.files:
                if ":" in file:
                    file = file.split(":")[0]

                for gadget in self.ropper_svc.getFileFor(name=file).gadgets:
                    f.write(f"{gadget}\n")


def main(args):
    g = Gadgetizer(args.files, args.bad_chars, args.output)

    tree = Tree(
        f'[bright_green][+][/bright_green] Categorized gadgets :: {" ".join(sys.argv)}'
    )
    g.add_gadgets_to_tree(tree)

    print(tree)

    with open(f"{g.output}.clean", "w") as f:
        print(tree, file=f)

    print(
        f"[bright_green][+][/bright_green] Collection of all gadgets written to [bright_blue]{args.output}[/bright_blue]"
    )
    g.save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Searches for clean, categorized gadgets from a given list of files"
    )

    parser.add_argument(
        "-f",
        "--files",
        help="space separated list of files from which to pull gadgets (optionally, add base address (libspp.dll:0x10000000))",
        required=True,
        nargs="+",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to omit from gadgets (default: 00)",
        default=["00"],
        nargs="+",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="name of output file where all (uncategorized) gadgets are written (default: found-gadgets.txt)",
        default="found-gadgets.txt",
    )

    args = parser.parse_args()

    main(args)
