#!/usr/bin/env python3
import argparse

import pykd


def main(args):
    choice_table = {"byte": "b", "ascii": "a", "unicode": "u"}
    command = f"s -{choice_table.get(args.type)} 0 L?80000000 {args.pattern}"
    print(f'[=] running {command}')
    result = pykd.dbgCommand(command)

    if result is None:
        return print('[*] No results returned')

    print(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Searches memory for the given search term"
    )

    parser.add_argument(
        "-t",
        "--type",
        default="byte",
        choices=["byte", "ascii", "unicode"],
        help="data type to search for (default: byte)",
    )
    parser.add_argument(
        "pattern",
        help="what you want to search for",
    )

    args = parser.parse_args()

    main(args)
