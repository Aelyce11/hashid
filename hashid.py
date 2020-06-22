import argparse
import sys
import re

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enter your hash")
    parser.add_argument(
        "hash", type=str, help="The hash you want to analyze.", nargs="?"
    )
    parser.add_argument(
        "--wikipedia", action="store_true", help="Description of hash"
    )
    parser.add_argument(
        "--list", action="store_true", help="List implemented hash algorithm."
    )

    return parser.parse_args()


def analyze(hash):
    result = []
    for algo in algorithm_list:
        if algo.get("regex") != "":
            if (algo.get("regex")).fullmatch(hash):
                result.append(algo["name"])

    if len(result) == 0 :
        return ["No matching algorithm found."]

    return result


def wiki(hashname):
    for algo in algorithm_list:
        if algo.get("name") == hashname:
            description = algo.get("wiki")
            if description == "":
                return "No wiki description"

            return description


algorithm_list = [
    {
        "name": "Blowfish-Eggdrop",
        "regex": re.compile(r'^\+[a-zA-Z0-9\/\.]{12}$'),
        "wiki": "Blowfish is a symmetric-key block cipher, designed in 1993 by Bruce Schneier and included in many cipher suites and encryption products.",
    },
    {
        "name": "Blowfish-OpenBSD",
        "regex": re.compile(r'^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9.\/\.]{53}$'),
        "wiki": "Blowfish is a symmetric-key block cipher, designed in 1993 by Bruce Schneier and included in many cipher suites and encryption products.",
    },
    {
        "name": "Blowfish-Crypt",
        "regex": re.compile(r'^\$2[axy]{0,1}\$[a-zA-Z0-9\/\.]{8}\$[a-zA-Z0-9.\/\.]{53}$'),
        "wiki": "Blowfish is a symmetric-key block cipher, designed in 1993 by Bruce Schneier and included in many cipher suites and encryption products.",
    },
    {
        "name": "Adler-32",
        "regex": re.compile(r'^[a-f0-9]{8}$'),
        "wiki": "Adler-32 is a checksum algorithm which was invented by Mark Adler in 1995,[1] and is a modification of the Fletcher checksum. Compared to a cyclic redundancy check of the same length, it trades reliability for speed (preferring the latter). Adler-32 is more reliable than Fletcher-16, and slightly less reliable than Fletcher-32.",
    },
    {
        "name": "Crc-32",
        "regex": re.compile(r'^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$', re.IGNORECASE),
        "wiki": "This is a practical algorithm for the CRC-32 variant of CRC. The CRCTable is a memoization of a calculation that would have to be repeated for each byte of the message (Computation of cyclic redundancy checks § Multi-bit computation).",
    },
    {
        "name": "Crc-32b",
        "regex": re.compile(r'^[a-f0-9]{8}$', re.IGNORECASE),
        "wiki": "This is a practical algorithm for the CRC-32 variant of CRC. The CRCTable is a memoization of a calculation that would have to be repeated for each byte of the message (Computation of cyclic redundancy checks § Multi-bit computation).",
    },
    {
        "name": "Fnv-132",
        "regex": re.compile(r'^[a-f0-9]{8}$', re.IGNORECASE),
        "wiki": "Fowler–Noll–Vo is a non-cryptographic hash function created by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo.",
    },
    # {
    #     "name": "Murmur3",
    #     "regex": "",
    #     "wiki": "MurmurHash is a non-cryptographic hash function suitable for general hash-based lookup. It was created by Austin Appleby in 2008[2] and is currently hosted on GitHub along with its test suite named 'SMHasher'. It also exists in a number of variants, all of which have been released into the public domain. The name comes from two basic operations, multiply (MU) and rotate (R), used in its inner loop.",
    # },
    {
        "name": "MD2",
        "regex": re.compile(r'^[a-fA-F0-9]{32}$'),
        "wiki": "The MD2 Message-Digest Algorithm is a cryptographic hash function developed by Ronald Rivest in 1989.[2] The algorithm is optimized for 8-bit computers. MD2 is specified in RFC 1319. Although MD2 is no longer considered secure, even as of 2014, it remains in use in public key infrastructures as part of certificates generated with MD2 and RSA. The 'MD' in MD2 stands for 'Message Digest'.",
    },
    {
        "name": "MD4",
        "regex": re.compile(r'^[a-fA-F0-9]{32}$'),
        "wiki": "The MD4 Message-Digest Algorithm is a cryptographic hash function developed by Ronald Rivest in 1990.[3] The digest length is 128 bits. The algorithm has influenced later designs, such as the MD5, SHA-1 and RIPEMD algorithms. The initialism 'MD' stands for 'Message Digest.'",
    },
    {
        "name": "MD5-Unix",
        "regex": re.compile(r'^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "MD5-Apr1",
        "regex": re.compile(r'^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "MD5-MyBB",
        "regex": re.compile(r'^[a-fA-F0-9]{32}:[a-z0-9]{8}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "MD5-Joomla",
        "regex": re.compile(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "MD5-Wordpress",
        "regex": re.compile(r'^\$P\$[a-zA-Z0-9\/\.]{31}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "MD5-PhpBB3",
        "regex": re.compile(r'^\$H\$[a-zA-Z0-9\/\.]{31}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "MD5",
        "regex": re.compile(r'^[a-fA-F0-9]{32}$'),
        "wiki": "The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption. It remains suitable for other non-cryptographic purposes, for example for determining the partition for a particular key in a partitioned database.",
    },
    {
        "name": "Ripmd-128",
        "regex": re.compile(r'^[a-f0-9]{32}(:.+)?$', re.IGNORECASE),
        "wiki": "RIPEMD (RIPE Message Digest) is a family of cryptographic hash functions developed in 1992 (the original RIPEMD) and 1996 (other variants). There are five functions in the family: RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256, and RIPEMD-320, of which RIPEMD-160 is the most common.",
    },
    {
        "name": "Fnv-164",
        "regex": re.compile(r'^[a-f0-9]{16}$', re.IGNORECASE),
        "wiki": "Fowler–Noll–Vo is a non-cryptographic hash function created by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo.",
    },
    {
        "name": "Haval-128",
        "regex": re.compile(r'^[a-f0-9]{32}(:.+)?$', re.IGNORECASE),
        "wiki": "HAVAL is a cryptographic hash function. Unlike MD5, but like most modern cryptographic hash functions, HAVAL can produce hashes of different lengths – 128 bits, 160 bits, 192 bits, 224 bits, and 256 bits. HAVAL also allows users to specify the number of rounds (3, 4, or 5) to be used to generate the hash. HAVAL was broken in 2004.",
    },
    {
        "name": "Tiger-128",
        "regex": re.compile(r'^[a-f0-9]{32}(:.+)?$', re.IGNORECASE),
        "wiki": "In cryptography, Tiger is a cryptographic hash function designed by Ross Anderson and Eli Biham in 1995 for efficiency on 64-bit platforms. The size of a Tiger hash value is 192 bits. Truncated versions (known as Tiger/128 and Tiger/160) can be used for compatibility with protocols assuming a particular hash size. Unlike the SHA-2 family, no distinguishing initialization values are defined; they are simply prefixes of the full Tiger/192 hash value. ",
    },
    {
        "name": "SHA-1",
        "regex": re.compile(r'^[a-fA-F0-9]{40}$'),
        "wiki": "In cryptography, SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function which takes an input and produces a 160-bit (20-byte) hash value known as a message digest – typically rendered as a hexadecimal number, 40 digits long. It was designed by the United States National Security Agency, and is a U.S. Federal Information Processing Standard.",
    },
    {
        "name": "SHA-1-Django",
        "regex": re.compile(r'^sha1\$.{0,32}\$[a-fA-F0-9]{40}$'),
        "wiki": "",
    },
    {
        "name": "SHA-1-Crypt",
        "regex": re.compile(r'^\$4\$[a-zA-Z0-9\.\/]{8}\$[a-zA-Z0-9\/\.]{1,}$'),
        "wiki": "",
    },
    {
        "name": "SHA-1-Oracle",
        "regex": re.compile(r'^[a-fA-F0-9]{48}$'),
        "wiki": "",
    },
    {
        "name": "SHA-256-Django",
        "regex": re.compile(r'^sha256\$.{0,32}\$[a-fA-F0-9]{64}$'),
        "wiki": "",
    },
    {
        "name": "SHA-384-Django",
        "regex": re.compile(r'^sha256\$.{0,32}\$[a-fA-F0-9]{96}$'),
        "wiki": "",
    },
    {
        "name": "SHA-512-Drupal",
        "regex": re.compile(r'^\$S\$[a-zA-Z0-9\/\.]{52}$'),
        "wiki": "",
    },
    {
        "name": "SSHA-1",
        "regex": re.compile(r'^(\{SSHA\})?[a-zA-Z0-9\+\/]{32,38}?(==)?$'),
        "wiki": "",
    },
    {
        "name": "SSHA-1-Base64",
        "regex": re.compile(r'^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$'),
        "wiki": "",
    },
    {
        "name": "SSHA-512-Base64",
        "regex": re.compile(r'^\{SSHA512\}[a-zA-Z0-9\+]{96}$'),
        "wiki": "",
    },
    {
        "name": "Ripemd-160",
        "regex": re.compile(r'^[a-f0-9]{40}(:.+)?$', re.IGNORECASE),
        "wiki": "RIPEMD (RIPE Message Digest) is a family of cryptographic hash functions developed in 1992 (the original RIPEMD) and 1996 (other variants). There are five functions in the family: RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256, and RIPEMD-320, of which RIPEMD-160 is the most common.",
    },
    {
        "name": "Joomla_old",
        "regex": re.compile(r'^([0-9a-zA-Z]{32}):(\d{16,32})$'),
        "wiki": "",
    },
    {
        "name": "Haval-160",
        "regex": re.compile(r'^[a-f0-9]{40}(:.+)?$', re.IGNORECASE),
        "wiki": "HAVAL is a cryptographic hash function. Unlike MD5, but like most modern cryptographic hash functions, HAVAL can produce hashes of different lengths – 128 bits, 160 bits, 192 bits, 224 bits, and 256 bits. HAVAL also allows users to specify the number of rounds (3, 4, or 5) to be used to generate the hash. HAVAL was broken in 2004.",
    },
    {
        "name": "DES-Unix",
        "regex": re.compile(r'^.{0,2}[a-zA-Z0-9\/\.]{11}$'),
        "wiki": "",
    },
    {
        "name": "Tiger-160",
        "regex": re.compile(r'^[a-f0-9]{40}(:.+)?$', re.IGNORECASE),
        "wiki": "In cryptography, Tiger is a cryptographic hash function designed by Ross Anderson and Eli Biham in 1995 for efficiency on 64-bit platforms. The size of a Tiger hash value is 192 bits. Truncated versions (known as Tiger/128 and Tiger/160) can be used for compatibility with protocols assuming a particular hash size. Unlike the SHA-2 family, no distinguishing initialization values are defined; they are simply prefixes of the full Tiger/192 hash value.",
    },
    {
        "name": "Haval-192",
        "regex": re.compile(r'^[a-f0-9]{48}$', re.IGNORECASE),
        "wiki": "HAVAL is a cryptographic hash function. Unlike MD5, but like most modern cryptographic hash functions, HAVAL can produce hashes of different lengths – 128 bits, 160 bits, 192 bits, 224 bits, and 256 bits. HAVAL also allows users to specify the number of rounds (3, 4, or 5) to be used to generate the hash. HAVAL was broken in 2004.",
    },
    {
        "name": "Tiger-192",
        "regex": re.compile(r'^[a-f0-9]{48}$', re.IGNORECASE),
        "wiki": "In cryptography, Tiger is a cryptographic hash function designed by Ross Anderson and Eli Biham in 1995 for efficiency on 64-bit platforms. The size of a Tiger hash value is 192 bits. Truncated versions (known as Tiger/128 and Tiger/160) can be used for compatibility with protocols assuming a particular hash size. Unlike the SHA-2 family, no distinguishing initialization values are defined; they are simply prefixes of the full Tiger/192 hash value.",
    },
    {
        "name": "SipHash",
        "regex": re.compile(r'^[a-f0-9]{16}:2:4:[a-f0-9]{32}$', re.IGNORECASE),
        "wiki": "SipHash is an add–rotate–xor (ARX) based family of pseudorandom functions created by Jean-Philippe Aumasson and Daniel J. Bernstein in 2012,[1]:165[2] in response to a spate of 'hash flooding' denial-of-service attacks in late 2011.",
    },
    {
        "name": "Sha-224",
        "regex": re.compile(r'^[a-fA-F0-9]{56}$'),
        "wiki": "SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National Security Agency (NSA) and first published in 2001. They are built using the Merkle–Damgård structure, from a one-way compression function itself built using the Davies–Meyer structure from a (classified) specialized block cipher.",
    },
    {
        "name": "Sha-256",
        "regex": re.compile(r'^[a-fA-F0-9]{64}$'),
        "wiki": "SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National Security Agency (NSA) and first published in 2001. They are built using the Merkle–Damgård structure, from a one-way compression function itself built using the Davies–Meyer structure from a (classified) specialized block cipher.",
    },
    {
        "name": "Ripemd-256",
        "regex": re.compile(r'^[a-f0-9]{64}(:.+)?$', re.IGNORECASE),
        "wiki": "RIPEMD (RIPE Message Digest) is a family of cryptographic hash functions developed in 1992 (the original RIPEMD) and 1996 (other variants). There are five functions in the family: RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256, and RIPEMD-320, of which RIPEMD-160 is the most common.",
    },
    {
        "name": "Snefru-256",
        "regex": re.compile(r'^(\$snefru\$)?[a-f0-9]{64}$', re.IGNORECASE),
        "wiki": "Snefru is a cryptographic hash function invented by Ralph Merkle in 1990 while working at Xerox PARC. The function supports 128-bit and 256-bit output. It was named after the Egyptian Pharaoh Sneferu, continuing the tradition of the Khufu and Khafre block ciphers.",
    },
    {
        "name": "Gost",
        "regex": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
        "wiki": "The GOST hash function, defined in the standards GOST R 34.11-94 and GOST 34.311-95 is a 256-bit cryptographic hash function. It was initially defined in the Russian national standard GOST R 34.11-94 Information Technology – Cryptographic Information Security – Hash Function. The equivalent standard used by other member-states of the CIS is GOST 34.311-95.",
    },
    {
        "name": "Haval-256",
        "regex": re.compile(r'^[a-f0-9]{64}(:.+)?$', re.IGNORECASE),
        "wiki": "HAVAL is a cryptographic hash function. Unlike MD5, but like most modern cryptographic hash functions, HAVAL can produce hashes of different lengths – 128 bits, 160 bits, 192 bits, 224 bits, and 256 bits. HAVAL also allows users to specify the number of rounds (3, 4, or 5) to be used to generate the hash. HAVAL was broken in 2004.",
    },
    {
        "name": "Ripemd-320",
        "regex": re.compile(r'^[a-f0-9]{80}$', re.IGNORECASE),
        "wiki": "RIPEMD (RIPE Message Digest) is a family of cryptographic hash functions developed in 1992 (the original RIPEMD) and 1996 (other variants). There are five functions in the family: RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256, and RIPEMD-320, of which RIPEMD-160 is the most common.",
    },
    {
        "name": "Sha-384",
        "regex": re.compile(r'^[a-f0-9]{96}$', re.IGNORECASE),
        "wiki": "SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National Security Agency (NSA) and first published in 2001. They are built using the Merkle–Damgård structure, from a one-way compression function itself built using the Davies–Meyer structure from a (classified) specialized block cipher.",
    },
    {
        "name": "Sha-512",
        "regex": re.compile(r'^[a-fA-F0-9]{128}$'),
        "wiki": "SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National Security Agency (NSA) and first published in 2001. They are built using the Merkle–Damgård structure, from a one-way compression function itself built using the Davies–Meyer structure from a (classified) specialized block cipher.",
    },
    {
        "name": "Whirlpool",
        "regex": re.compile(r'^[a-f0-9]{128}(:.+)?$', re.IGNORECASE),
        "wiki": "In computer science and cryptography, Whirlpool (sometimes styled WHIRLPOOL) is a cryptographic hash function. It was designed by Vincent Rijmen (co-creator of the Advanced Encryption Standard) and Paulo S. L. M. Barreto, who first described it in 2000.",
    },
    {
        "name": "Oracle-11g",
        "regex": re.compile(r'^S:[A-Z0-9]{60}$'),
        "wiki": "",
    },
    {
        "name": "MySQL-5.x",
        "regex": re.compile(r'^[a-f0-9]{40}$'),
        "wiki": "",
    },
    {
        "name": "MySQL-3.x",
        "regex": re.compile(r'^[a-fA-F0-9]{16}$'),
        "wiki": "",
    },
    {
        "name": "OSX-v10.7",
        "regex": re.compile(r'^[a-fA-F0-9]{136}$'),
        "wiki": "",
    },
    {
        "name": "OSX-v10.8",
        "regex": re.compile(r'^\$ml\$[a-fA-F0-9\$]{199}$'),
        "wiki": "",
    },
    {
        "name": "MSSQL-2000",
        "regex": re.compile(r'^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$'),
        "wiki": "",
    },
    {
        "name": "MSSQL-2005",
        "regex": re.compile(r'^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$'),
        "wiki": "",
    },
    {
        "name": "MSSQL-2012",
        "regex": re.compile(r'^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$'),
    },
    {
        "name": "Tiger-160-HMAC",
        "regex": re.compile(r'^[a-z0-9]{40}$'),
        "wiki": "",
    },
    {
        "name": "Minecraft-Authme",
        "regex": re.compile(r'^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$'), # NO TEST FOUND
        "wiki": "",
    },
    {
        "name": "Lineage_II-C4",
        "regex": re.compile(r'^Ox[a-fA-F0-9]{32}$'), # NO TEST FOUND
        "wiki": "",
    },
    {
        "name": "CRC-96-ZIP",
        "regex": re.compile(r'^[a-fA-F0-9]{24}$'), # NO TEST FOUND
        "wiki": "",
    },
]

def main() -> None:
    args = parse_args()

    if args.hash:
        for i in analyze(args.hash):
            print(i)
            if args.wikipedia:
                print(wiki(i))
        exit(0)

    if args.list:
        for i in algorithm_list:
            print(i["name"])
        exit(0)


if __name__ == "__main__":
    main()
