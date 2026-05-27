"""
Encrypt and decrypt Juniper $9$ reversible passwords.

The $9$ algorithm is a proprietary Juniper substitution cipher that is
deterministic and device-independent: the same plaintext can be encrypted
on any Juniper device and decrypted on any other, with no node-specific
secret involved.

This is a Python implementation of the algorithm. It is based on
`Crypt::Juniper` (Perl, Kevin Brintnall) and Matt Hite's Python 2 port
at https://github.com/mhite/junosdecode.

Public API:
    decrypt(ciphertext: str) -> str
    encrypt(plaintext: str) -> str
    check(ciphertext: str, other: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import argparse
import random
import sys

__version__ = "0.1.0"

__all__ = ["decrypt", "encrypt", "check", "__version__"]

MAGIC = "$9$"
FAMILY = ["QzF3n6/9CAtpu0O", "B1IREhcSyrleKvMW8LXx", "7N-dVbwsY2g4oaJZGUDj", "iHkq.mPf5T"]
EXTRA = {c: 3 - i for i, f in enumerate(FAMILY) for c in f}
ALPHA = "".join(FAMILY)
NUM = {c: i for i, c in enumerate(ALPHA)}
ENCODING = [[1, 4, 32], [1, 16, 32], [1, 8, 32], [1, 64], [1, 32], [1, 4, 16, 128], [1, 32, 64]]


def _gap(c1: str, c2: str) -> int:
    return (NUM[c2] - NUM[c1]) % len(ALPHA) - 1


def decrypt(ciphertext: str) -> str:
    """Decrypt a Juniper $9$ ciphertext back to plaintext."""
    if not ciphertext.startswith(MAGIC):
        raise ValueError(f"Not a Juniper $9$ string: must start with {MAGIC}")
    chars = ciphertext[len(MAGIC):]
    if not chars:
        raise ValueError("Empty $9$ payload")
    first = chars[0]
    if first not in NUM:
        raise ValueError(f"Invalid start character {first!r}: not in $9$ alphabet")
    chars = chars[1 + EXTRA[first]:]
    prev = first
    result: list[str] = []
    while chars:
        weights = ENCODING[len(result) % len(ENCODING)]
        nibble = chars[: len(weights)]
        chars = chars[len(weights):]
        val = 0
        for c, w in zip(nibble, weights):
            if c not in NUM:
                raise ValueError(f"Character {c!r} not in $9$ alphabet: ciphertext may be invalid")
            val += _gap(prev, c) * w
            prev = c
        result.append(chr(val % 256))
    return "".join(result)


def encrypt(plaintext: str) -> str:
    """Encrypt plaintext to a Juniper $9$ ciphertext.

    Output is non-deterministic: random filler characters mean each call
    returns a different ciphertext for the same plaintext. All of them
    decrypt back to the same plaintext. `random` (not `secrets`) is used
    deliberately, since $9$ is a substitution cipher with no real
    cryptographic strength: a stronger RNG buys nothing.
    """
    start = random.choice(ALPHA)
    result = [MAGIC, start]
    for _ in range(EXTRA[start]):
        result.append(random.choice(ALPHA))
    prev = start
    for i, ch in enumerate(plaintext):
        weights = ENCODING[i % len(ENCODING)]
        val = ord(ch)
        gaps: list[int] = []
        for w in reversed(weights):
            gaps.append(val // w)
            val = val % w
        for gap in reversed(gaps):
            c = ALPHA[(NUM[prev] + gap + 1) % len(ALPHA)]
            result.append(c)
            prev = c
    return "".join(result)


def check(ciphertext: str, other: str) -> tuple[str, str, bool]:
    """Decrypt `ciphertext` and compare to `other`.

    `other` may be a plaintext, or another $9$ value (auto-detected by
    the $9$ prefix). Returns (plain_a, plain_b, match).
    """
    plain_a = decrypt(ciphertext)
    plain_b = decrypt(other) if other.startswith(MAGIC) else other
    return plain_a, plain_b, plain_a == plain_b


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="juniper9-crypt",
        description="Encrypt, decrypt, or compare Juniper $9$ passwords.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--decrypt", metavar="CIPHERTEXT", help="Decrypt a $9$ value")
    group.add_argument("--encrypt", metavar="PLAINTEXT", help="Encrypt a plaintext value")
    group.add_argument(
        "--check",
        nargs=2,
        metavar=("CIPHERTEXT", "VALUE"),
        help="Decrypt and compare. VALUE is a plaintext or another $9$ value. Exit 0 on match, 1 on mismatch.",
    )
    args = parser.parse_args(argv)

    try:
        if args.decrypt:
            print(decrypt(args.decrypt))
        elif args.encrypt:
            print(encrypt(args.encrypt))
        elif args.check:
            plain_a, plain_b, match = check(*args.check)
            print(f"Value 1   : {plain_a!r}")
            print(f"Value 2   : {plain_b!r}")
            print(f"Match     : {'YES' if match else 'NO'}")
            return 0 if match else 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
