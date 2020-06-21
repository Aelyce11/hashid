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

    if len(result) == 0 :
        return ["No matching algorithm found."]

    return result


algorithm_list = {
    "Blowfish-Eggdrop": re.compile(r"^\+[a-zA-Z0-9\/\.]{12}$"),
    "Blowfish-OpenBSD": re.compile(r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9.\/\.]{53}$"),
    "Blowfish-Crypt": re.compile(
        r"^\$2[axy]{0,1}\$[a-zA-Z0-9\/\.]{8}\$[a-zA-Z0-9.\/\.]{53}$"
    ),
    "MD2": re.compile(r"^[a-fA-F0-9]{32}$"),
    "MD4": re.compile(r"^[a-fA-F0-9]{32}$"),
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "MD5-Unix": re.compile(r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
    "MD5-Apr1": re.compile(r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
    "MD5-MyBB": re.compile(r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
    "MD5-Joomla": re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
    "MD5-Wordpress": re.compile(r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
    "MD5-PhpBB3": re.compile(r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
    "SHA-1-Hex": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA-1-Django": re.compile(r"^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
    "SHA-1-Crypt": re.compile(r"^\$4\$[a-zA-Z0-9\.\/]{8}\$[a-zA-Z0-9\/\.]{1,}$"),
    "SHA-1-Oracle": re.compile(r"^[a-fA-F0-9]{48}$"),
    "SHA-224": re.compile(r"^[a-fA-F0-9]{56}$"),
    "SHA-256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "SHA-256-Django": re.compile(r"^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
    "SHA-384": re.compile(r"^[a-fA-F0-9]{96}$"),
    "SHA-384-Django": re.compile(r"^sha256\$.{0,32}\$[a-fA-F0-9]{96}$"),
    "SHA-512": re.compile(r"^[a-fA-F0-9]{128}$"),
    "SHA-512-Drupal": re.compile(r"^\$S\$[a-zA-Z0-9\/\.]{52}$"),
    "SSHA-1": re.compile(r"^(\{SSHA\})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
    "SSHA-1-Base64": re.compile(r"^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
    "SSHA-512-Base64": re.compile(r"^\{SSHA512\}[a-zA-Z0-9\+]{96}$"),
    # TEST ALL ABOVE
    "Joomla_old": re.compile(r"^([0-9a-zA-Z]{32}):(\d{16,32})$"),
    "DES-Unix": re.compile(r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
    # "Minecraft-Authme": re.compile(r"^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
    "Lotus_Domino-6": re.compile(r"^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
    # "Lineage_II-C4": re.compile(r"^Ox[a-fA-F0-9]{32}$"),
    # "CRC-96-ZIP": re.compile(r"^[a-fA-F0-9]{24}$"),
    "Ripemd-320": re.compile(r"^[A-Fa-f0-9]{80}$"),
    "Oracle-11g": re.compile(r"^S:[A-Z0-9]{60}$"),
    "MySQL-5.x": re.compile(r"^[a-f0-9]{40}$"),
    "MySQL-3.x": re.compile(r"^[a-fA-F0-9]{16}$"),
    "OSX-v10.7": re.compile(r"^[a-fA-F0-9]{136}$"),
    "OSX-v10.8": re.compile(r"^\$ml\$[a-fA-F0-9\$]{199}$"),
    "MSSQL-2000": re.compile(r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
    "MSSQL-2005": re.compile(r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
    "MSSQL-2012": re.compile(r"^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
    "Tiger-160-HMAC": re.compile(r"^[a-z0-9]{40}$"),
    "Adler-32": re.compile(r"^[a-f0-9]{8}$"),
}

# TODO: add crc-32

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
