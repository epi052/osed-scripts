#!/usr/bin/env python3
import re
import argparse

from rich import print
from rich.tree import Tree
from rich.markup import escape
from ropper import RopperService


INSTRUCTIONS = (
    "mov",
    "push",
    "pop",
    "xchg",
    "xor",
    "add",
    "sub",
    "inc",
    "dec",
    "neg",
    "jmp",
    "call",
    "leave",
)


class Gadgetizer:
    def __init__(self, files, badbytes, output):
        self.files = files
        self.output = output
        self.badbytes = "".join(
            badbytes
        )  # ropper's badbytes option has to be an instance of str
        self.ropper_svc = self.get_ropper_service()

    @staticmethod
    def prettify(gadget):
        # things like dword ptr [eax] need to be escaped for rich's markup
        escaped = escape(str(gadget))
        escaped = re.sub(r"(0x[0-9a-fA-F]+(?!\]))", r"[blue]\1[/]", escaped)
        escaped = escaped.replace(f"ret", f"[red]ret[/]")

        for instr in INSTRUCTIONS:
            escaped = escaped.replace(
                f" {instr}", f" [steel_blue1]{instr}[/]"
            )

        return escaped

    def get_ropper_service(self):
        # not all options need to be given
        options = {
            "color": False,
            "badbytes": self.badbytes,
            "type": "rop",  # rop, jop, sys, all; default: all
        }  # if gadgets are printed, use detailed output; default: False

        rs = RopperService(options)
        for file in self.files:
            rs.addFile(file, arch="x86")
            # rs.setImageBaseFor(file, 0x1100000)

        rs.loadGadgetsFor()

        return rs

    def get_gadgets(self, search_str, quality=1, strict=False):
        gadgets = [
            g for _, g in self.ropper_svc.search(search=search_str, quality=quality)
        ]  # could be memory hog

        if not gadgets and quality < self.ropper_svc.options.inst_count and not strict:
            # attempt highest quality gadget, continue requesting with lower quality until something is returned
            return self.get_gadgets(search_str, quality=quality + 1)

        return gadgets

    def _search_gadget(self, title, search_strs):
        title = f"[bright_yellow]{title}[/bright_yellow] gadgets"
        tree = Tree(title)

        for search_str in search_strs:
            for gadget in self.get_gadgets(search_str):
                pretty = Gadgetizer.prettify(gadget)
                tree.add(pretty)

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
        with open(self.output, 'w') as f:
            for file in self.files:
                for gadget in self.ropper_svc.getFileFor(name=file).gadgets:
                    f.write(f'{gadget}\n')


def main(args):
    g = Gadgetizer(args.files, args.bad_chars, args.output)

    tree = Tree('[bright_green][+][/bright_green] Categorized gadgets')
    g.add_gadgets_to_tree(tree)

    print(tree)

    print(f'[bright_green][+][/bright_green] Collection of all gadgets written to [bright_blue]{args.output}[/bright_blue]')
    g.save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Searches for clean, categorized gadgets from a given list of files"
    )

    parser.add_argument(
        "-f",
        "--files",
        help="space separated list of files from which to pull gadgets",
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
    parser.add_argument('-o', '--output', help='name of output file where all (uncategorized) gadgets are written (default: found-gadgets.txt)', default='found-gadgets.txt')

    args = parser.parse_args()

    main(args)
