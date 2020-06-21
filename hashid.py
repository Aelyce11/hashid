import argparse
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enter your hash")
    parser.add_argument(
        "hash", type=str, help="The hash you want to analyze.", nargs="?"
    )
    parser.add_argument(
        "--list", action="store_true", help="List implemented hash algorithm."
    )

    return parser.parse_args()


def analyze(hash):
    alg = {
        "Adler-32": 8,
        "Crc-32": 8,
        "Crc-32b": 8,
        "Fnv-132": 8,
        "Fnv-164": 16,
        "MD2": 32,
        "MD4": 32,
        "MD5": 32,
        "Ripmd-128": 32,
        "Snefru": 32,
        "Sha1": 40,
        "Ripemd-160": 40,
        "SipHash": 53,
        "Sha-224": 56,
        "Sha-256": 64,
        "Ripemd-256": 64,
        "Snefru-256": 64,
        "Ghost": 64,
        "Ripemd-320": 80,
        "Sha-384": 96,
        "Sha-512": 128,
        "Whirlpool": 128,
    }
    result = []
    for i in alg.items():
        if len(hash) == i[1]:
            result.append(i[0])

    if len(result) != 0:
        return result
    return ["Unknown hash algorithm"]


def main() -> None:
    args = parse_args()

    for i in analyze(args.hash):
        print(i)

    # if args.list:
    #     show_hash_list()
    #     exit(0)


if __name__ == "__main__":
    main()
