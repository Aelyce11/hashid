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
    result_all = []
    result_most = []
    result_least = []

    for i in algorithm_list_len.items():
        if len(hash) == i[1]:
            result_all.append(i[0])

    if len(result_all) == 0:
        return ["No correspondance found."]

    for i in result_all:
        if i in algorithm_list_charset.keys():
            if (algorithm_list_charset.get(i)).fullmatch(hash):
                result_most.append(i)
        else:
            result_least.append(i)

    m = ["MOST PROBABLE ALGORITHM :"] + result_most
    l = ["LESS PROBABLE ALGORITHM :"] + result_least

    n = m + [""] + l

    return n


algorithm_list_charset = {
    "MD5": re.compile(r"[a-fA-F0-9]*"),
    "Sha-1": re.compile(r"[a-fA-F0-9]*"),
    "Sha-224": re.compile(r"[a-fA-F0-9]*"),
    "Sha-256": re.compile(r"[a-fA-F0-9]*"),
    "Sha-384": re.compile(r"[a-fA-F0-9]*"),
    "Sha-512": re.compile(r"[a-fA-F0-9]*"),
    # "": re.compile(r""),
}

algorithm_list_len = {
    "Djb-2": 5,
    "Adler-32": 8,
    "Crc-32": 8,
    "Crc-32b": 8,
    "Fnv-132": 8,
    "Fnv-1a32": 8,
    "Joaat": 8,
    "Murmur3": 8,
    "Farm_hash_fingerprint-32": 8,
    "Fnv-1a52": 13,
    "Fnv-1a64": 16,
    "Fnv-164": 16,
    "Farm_hash_fingerprint-64": 16,
    "MD2": 32,
    "MD4": 32,
    "MD5": 32,
    "Ripmd-128": 32,
    "Snefru": 32,
    "Fnv-1a128": 32,
    "Haval-128_3": 32,
    "Haval-128_4": 32,
    "Haval-128_5": 32,
    "Tiger-128": 32,
    "Tiger-128_4": 32,
    "Sha1": 40,
    "Ripemd-160": 40,
    "Haval-160_3": 40,
    "Haval-160_4": 40,
    "Haval-160_5": 40,
    "Tiger-160": 40,
    "Tiger-160_3": 40,
    "Tiger-160_4": 40,
    "Haval-192_3": 48,
    "Haval-192_4": 48,
    "Haval-192_5": 48,
    "Tiger-192": 48,
    "Tiger-192_4": 48,
    "SipHash": 53,
    "Sha-224": 56,
    "Haval-224_3": 56,
    "Haval-224_4": 56,
    "Haval-224_5": 56,
    "Sha-256": 64,
    "Ripemd-256": 64,
    "Snefru-256": 64,
    "Ghost": 64,
    "Haval-256_3": 64,
    "Haval-256_4": 64,
    "Haval-256_5": 64,
    "Ripemd-320": 80,
    "Sha-384": 96,
    "Sha-512": 128,
    "Whirlpool": 128,
    "Fnv-1a512": 128,
    "Fnv-1a1024": 256,
}

# BLAKE


def main() -> None:
    args = parse_args()

    if args.hash:
        for i in analyze(args.hash):
            print(i)
        exit(0)

    if args.list:
        for i in algorithm_list_len.keys():
            print(i)
        exit(0)


if __name__ == "__main__":
    main()
