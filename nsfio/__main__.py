from pathlib import Path
import sys

from nsfio import class_from_name

from nsfio.keys import ConsoleKeys


def main():
    console_keys = ConsoleKeys(Path.home() / ".switch" / "prod.keys")

    f = sys.argv[1]

    cls = class_from_name(f)
    with open(f, 'rb') as fp:
        data = fp.read()

    with cls(console_keys=console_keys).from_bytes(data) as obj:
        print(obj)

if __name__ == "__main__":
    main()
