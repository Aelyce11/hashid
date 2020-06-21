import argparse
import sys
import re


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
    result = []

    for i in algorithm_list.keys():
        if (algorithm_list.get(i)).fullmatch(hash):
            result.append(i)

    return result


algorithm_list = {
    "Djb-2": re.compile(r".{5}"),
    "Adler-32": re.compile(r".{8}"),
    "Crc-32": re.compile(r".{8}"),
    "Crc-32b": re.compile(r".{8}"),
    "Fnv-132": re.compile(r".{8}"),
    "Fnv-1a32": re.compile(r".{8}"),
    "Joaat": re.compile(r".{8}"),
    "Murmur3": re.compile(r".{8}"),
    "Farm_hash_fingerprint-32": re.compile(r".{8}"),
    "Fnv-1a52": re.compile(r".{13}"),
    "Fnv-1a64": re.compile(r".{16}"),
    "Fnv-164": re.compile(r".{16}"),
    "Farm_hash_fingerprint-64": re.compile(r".{16}"),
    "MD2": re.compile(r"[a-fA-F0-9]{32}"),
    "MD4": re.compile(r"[a-fA-F0-9]{32}"),
    "MD5": re.compile(r"[a-fA-F0-9]{32}"),
    "Ripmd-128": re.compile(r".{32}"),
    "Snefru": re.compile(r".{32}"),
    "Fnv-1a128": re.compile(r".{32}"),
    "Haval-128_3": re.compile(r".{32}"),
    "Haval-128_4": re.compile(r".{32}"),
    "Haval-128_5": re.compile(r".{32}"),
    "Tiger-128": re.compile(r".{32}"),
    "Tiger-128_4": re.compile(r".{32}"),
    "Sha-1": re.compile(r"[a-fA-F0-9]{40}"),
    "Ripemd-160": re.compile(r".{40}"),
    "Haval-160_3": re.compile(r".{40}"),
    "Haval-160_4": re.compile(r".{40}"),
    "Haval-160_5": re.compile(r".{40}"),
    "Tiger-160": re.compile(r".{40}"),
    "Tiger-160_3": re.compile(r".{40}"),
    "Tiger-160_4": re.compile(r".{40}"),
    "Haval-192_3": re.compile(r".{48}"),
    "Haval-192_4": re.compile(r".{48}"),
    "Haval-192_5": re.compile(r".{48}"),
    "Tiger-192": re.compile(r".{48}"),
    "Tiger-192_4": re.compile(r".{48}"),
    "SipHash": re.compile(r".{53}"),
    "Sha-224": re.compile(r"[a-fA-F0-9]{56}"),
    "Haval-224_3": re.compile(r".{56}"),
    "Haval-224_4": re.compile(r".{56}"),
    "Haval-224_5": re.compile(r".{56}"),
    "Sha-256": re.compile(r"[a-fA-F0-9]{64}"),
    "Ripemd-256": re.compile(r".{64}"),
    "Snefru-256": re.compile(r".{64}"),
    "Ghost": re.compile(r".{64}"),
    "Haval-256_3": re.compile(r".{64}"),
    "Haval-256_4": re.compile(r".{64}"),
    "Haval-256_5": re.compile(r".{64}"),
    "Ripemd-320": re.compile(r".{80}"),
    "Sha-384": re.compile(r"[a-fA-F0-9]{96}"),
    "Sha-512": re.compile(r"[a-fA-F0-9]{128}"),
    "Whirlpool": re.compile(r".{128}"),
    "Fnv-1a512": re.compile(r".{128}"),
    "Fnv-1a1024": re.compile(r".{256}"),
}

# BLAKE


def main() -> None:
    args = parse_args()

    if args.hash:
        for i in analyze(args.hash):
            print(i)
        exit(0)

    if args.list:
        for i in algorithm_list.keys():
            print(i)
        exit(0)


if __name__ == "__main__":
    main()
