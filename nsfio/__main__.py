from pathlib import Path
import sys

from nsfio import class_from_name

from nsfio.keys import ConsoleKeys
import logging


def main():
    logging.basicConfig(level=logging.INFO, format="[%(levelname)8s] %(message)s")
    console_keys = ConsoleKeys(Path.home() / ".switch" / "prod.keys")

    f = sys.argv[1]

    cls = class_from_name(f)
    with cls(console_keys=console_keys).from_file(f) as obj:
        print(obj)

if __name__ == "__main__":
    main()
