#!/usr/bin/env python3
import re
import sys
import shutil
import argparse
import tempfile
import subprocess
from pathlib import Path
import multiprocessing
import platform

og_print = print
from rich import print
from rich.tree import Tree
from rich.markup import escape
from ropper import RopperService


class Gadgetizer:
    def __init__(self, files, badbytes, output, arch, color):
        self.arch = arch
        self.color = color
        self.files = files
        self.output = output
        self.badbytes = "".join(
            badbytes
        )  # ropper's badbytes option has to be an instance of str
        self.ropper_svc = self.get_ropper_service()
        self.addresses = set()

    def get_ropper_service(self):
        # not all options need to be given
        options = {
            "color": self.color,
            "badbytes": self.badbytes,
            "type": "rop",
        }  # if gadgets are printed, use detailed output; default: False

        rs = RopperService(options)

        for file in self.files:
            if ":" in file:
                file, base = file.split(":")
                rs.addFile(file, arch=self.arch)
                rs.clearCache()
                rs.setImageBaseFor(name=file, imagebase=int(base, 16))
            else:
                rs.addFile(file, arch=self.arch)
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
        gadget_filter = re.compile(r'ret 0x[0-9a-fA-F]{3,};')  # filter out rets larger than 255

        for search_str in search_strs:
            for file, gadget in self.get_gadgets(search_str):
                if gadget_filter.search(gadget.simpleString()):
                    # not sure how to filter large ret sizes within ropper's search functionality, so doing it here
                    continue
                tree.add(f"{escape(str(gadget)).replace(':', '  #', 1)} :: {file}")
                self.addresses.add(hex(gadget.address))

        return tree

    def add_gadgets_to_tree(self, tree):
        zeroize_strs = []
        reg_prefix = "e" if self.arch == "x86" else "r"

        eip_to_esp_strs = [
            f"jmp {reg_prefix}sp;",
            "leave;",
            f"mov {reg_prefix}sp, ???;",
            f"call {reg_prefix}sp;",
        ]

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
        tree.add(self._search_gadget("add register", [f"add ???, {reg_prefix}??;"]))
        tree.add(
            self._search_gadget("subtract register", [f"sub ???, {reg_prefix}??;"])
        )
        tree.add(self._search_gadget("negate register", [f"neg {reg_prefix}??;"]))
        tree.add(self._search_gadget("xor register", [f"xor {reg_prefix}??, 0x????????"]))
        tree.add(self._search_gadget("push", [f"push {reg_prefix}??;"]))
        tree.add(self._search_gadget("pushad", [f"pushad;"]))
        tree.add(self._search_gadget("pop", [f"pop {reg_prefix}??;"]))
        tree.add(
            self._search_gadget(
                "push-pop", [f"push {reg_prefix}??;.*pop {reg_prefix}??;*"]
            )
        )

        for reg in [
            f"{reg_prefix}ax",
            f"{reg_prefix}bx",
            f"{reg_prefix}cx",
            f"{reg_prefix}dx",
            f"{reg_prefix}si",
            f"{reg_prefix}di",
        ]:
            zeroize_strs.append(f"xor {reg}, {reg};")
            zeroize_strs.append(f"sub {reg}, {reg};")
            zeroize_strs.append(f"lea [{reg}], 0;")
            zeroize_strs.append(f"mov {reg}, 0;")
            zeroize_strs.append(f"and {reg}, 0;")
            eip_to_esp_strs.append(f"xchg {reg_prefix}sp, {reg}; jmp {reg};")
            eip_to_esp_strs.append(f"xchg {reg_prefix}sp, {reg}; call {reg};")

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


def add_missing_gadgets(ropper_addresses: set, in_file, outfile, bad_bytes, base_address=None):
    """ for w/e reason rp++ finds signficantly more gadgets, this function adds them to ropper's dump of all gadgets """
    fname = ''
    if platform.system() == 'Linux':
        fname = 'rp-lin-x64'
    elif platform.system() == "Darwin":
        fname = 'rp-osx-x64'

    rp = Path('~/.local/bin/' + fname).expanduser().resolve()

    if not rp.exists():
        print(f"[bright_yellow][*][/bright_yellow] rp++ not found, downloading...")
        rp.parent.mkdir(parents=True, exist_ok=True)

        wget = shutil.which('wget')
        if not wget:
            print(f"[bright_red][!][/bright_red] wget not found, please install it or add -s|--skip-rp to your command")
            return

        subprocess.run(f'{wget} https://github.com/0vercl0k/rp/releases/download/v2.0.2/{fname} -O {rp}'.split())


        rp.chmod(mode=0o755)

    with tempfile.TemporaryFile(mode='w+', suffix='osed-rop') as tmp_file, open(outfile, 'a') as af:

        command = f'{rp} -r5 -f {in_file} --unique'

        if bad_bytes:
            bad_bytes = ''.join([f"\\x{byte}" for byte in bad_bytes])
            command += f' --bad-bytes={bad_bytes}'
        if base_address:
            command += f' --va={base_address}'

        print(f"[bright_green][+][/bright_green] running '{command}'")
        subprocess.run(command.split(), stdout=tmp_file)

        tmp_file.seek(0)

        for line in tmp_file.readlines():
            if not line.startswith('0x'):
                continue

            rp_address = line.split(':')[0]

            if rp_address not in ropper_addresses:
                truncated = line.rsplit(';', maxsplit=1)[0]
                af.write(f'{truncated}\n')


def clean_up_all_gadgets(outfile):
    """ normalize output from ropper and rp++ """
    normal_spaces = re.compile(r'[ ]{2,}')
    normal_semicolon = re.compile(r'[ ]+?;')

    with tempfile.TemporaryFile(mode='w+', suffix='osed-rop') as tmp_file, open(outfile, 'r+') as f:
        for line in f.readlines():
            # rp++ adds a bunch of spaces around everything. normalize them for easier regex
            line = normal_spaces.sub(' ', line)

            # rp++ adds a bunch of spaces around semi-colons, ropper does not. normalize them for easier regex
            line = normal_semicolon.sub(';', line)

            # change "0x97753db7: add ..." to "0x97753db7  # add ..." for easy addition to source code
            line = line.replace(':', '  #', 1)

            tmp_file.write(line)

        tmp_file.seek(0)

        f.seek(0)
        f.write(tmp_file.read())
        # tmp_file became shorter than the original, need to remove the old contents that persist beyond
        # what was just written
        f.truncate()


def print_useful_regex(outfile, arch):

    reg_prefix = "e" if arch == "x86" else "r"
    len_sort = "| awk '{ print length, $0 }' | sort -n -s -r | cut -d' ' -f2- | tail"
    any_reg = f'{reg_prefix}..'

    search_terms = list()
    search_terms.append(f'(jmp|call) {reg_prefix}sp;')
    search_terms.append(fr'mov {any_reg}, \[{any_reg}\];')
    search_terms.append(fr'mov \[{any_reg}\], {any_reg};')
    search_terms.append(fr'mov {any_reg}, {any_reg};')
    search_terms.append(fr'xchg {any_reg}, {any_reg};')
    search_terms.append(fr'push {any_reg};.*pop {any_reg};')
    search_terms.append(fr'inc {any_reg};')
    search_terms.append(fr'dec {any_reg};')
    search_terms.append(fr'neg {any_reg};')
    search_terms.append(fr'push {any_reg};')
    search_terms.append(fr'pop {any_reg};')
    search_terms.append('pushad;')
    search_terms.append(fr'and {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'xor {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'add {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'sub {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'(lea|mov|and) \[?{any_reg}\]?, 0;')

    print(f"[bright_green][+][/bright_green] helpful regex for searching within {outfile}\n")

    for term in search_terms:
        og_print(f"egrep '{term}' {outfile} {len_sort}")


def main(args):
    if platform.system() == "Darwin":
        #Fix issue with Ropper in macOS -> AttributeError: 'Ropper' object has no attribute '__gatherGadgetsByEndings'
        multiprocessing.set_start_method('fork')
    
    g = Gadgetizer(args.files, args.bad_chars, args.output, args.arch, args.color)

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

    if args.skip_rp:
        return

    for file in args.files:
        if ":" in file:
            file, base = file.split(":")
            add_missing_gadgets(g.addresses, file, args.output, bad_bytes=args.bad_chars, base_address=base)
        else:
            add_missing_gadgets(g.addresses, file, args.output, bad_bytes=args.bad_chars)

    clean_up_all_gadgets(args.output)
    print_useful_regex(args.output, args.arch)


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
        help="space separated list of bad chars to omit from gadgets, e.g., 00 0a (default: empty)",
        default=[],
        nargs="+",
    )
    parser.add_argument(
        "-a",
        "--arch",
        choices=["x86", "x86_64"],
        help="architecture of the given file (default: x86)",
        default="x86",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="name of output file where all (uncategorized) gadgets are written (default: found-gadgets.txt)",
        default="found-gadgets.txt",
    )
    parser.add_argument(
        "-c",
        "--color",
        help="colorize gadgets in output (default: False)",
        action='store_true',
    )
    parser.add_argument(
        "-s",
        "--skip-rp",
        help="don't run rp++ to find additional gadgets (default: False)",
        action='store_true',
    )

    args = parser.parse_args()

    main(args)
