import argparse
from pathlib import Path
import sys

from nsfio import class_from_name

from nsfio.keys import ConsoleKeys
import logging


def _tree(obj, level=0):
    print("  "*level, obj, sep="")
    for x in obj.children:
        _tree(x, level+1)


def main():
    parser = argparse.ArgumentParser(description="Show the contents of Switch files")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-k", "--keys", help="prod.keys (default: ~/.switch/prod.keys)")
    parser.add_argument("file")
    args = parser.parse_args()

    logging.basicConfig(
        level=(logging.INFO, logging.DEBUG, logging.IOTRACE)[max(0, min(args.verbose, 2))],
        format="[%(levelname)8s] %(message)s"
    )
    console_keys = ConsoleKeys(args.keys or (Path.home() / ".switch" / "prod.keys"))


    cls = class_from_name(args.file)
    with cls(console_keys=console_keys).from_file(args.file) as obj:
        _tree(obj)

if __name__ == "__main__":
    main()
