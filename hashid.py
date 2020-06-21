import argparse

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enter your hash")
    parser.add_argument(
        "hash",
        type=str,
        help="The hash you want to analyze.",
        nargs="?",
    )
    parser.add_argument("--list", action="store_true", help="List implemented hash algorithm.")

    return parser.parse_args()

def analyze(hash):
    if sys.getSizeOf(hash) == 128:
        return "size 128"

    return "unknown hash algorithm"


def main() -> None:
    args = parse_args()
    if args.list:
        show_hash_list()
        exit(0)


if __name__ == "__main__":
    main()