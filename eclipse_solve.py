#!/usr/bin/env python3
"""Offline re-implementation of Eclipse.apk's Native.derive (libeclipse.so).

Usage:
    python3 eclipse_solve.py <file> [<file> ...]   # test files as in.bin
    python3 eclipse_solve.py -s "<text>" [...]      # test literal strings
Prints the decrypted output; a correct key gives Null0rigin{...}.
"""
import hashlib
import struct
import sys

SALT = bytes.fromhex("9d2a417c0eb358f126cd740ae8531f62")
CT = bytes.fromhex(
    "200bfb3fff3d2a0ef143bbf1f55be54d6248ac94074476f325eedddf343b5400"
    "97943df4697ed3b2905b1135952aee2893770e9f024f247e3187"
)
ROUNDS = 0x400000


def derive(data: bytes) -> bytes:
    h = hashlib.sha256(data).digest()
    for _ in range(ROUNDS):
        h = hashlib.sha256(h).digest()
    ks = b"".join(
        hashlib.sha256(h + SALT + struct.pack("<I", i)).digest() for i in range(2)
    )
    return bytes(c ^ k for c, k in zip(CT, ks))


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    literal = args[0] == "-s"
    for arg in args[1:] if literal else args:
        data = arg.encode() if literal else open(arg, "rb").read()
        out = derive(data)
        ok = all(32 <= b < 127 for b in out)
        print(("FLAG  " if ok else "wrong ") + (out.decode() if ok else out.hex()), "<-", arg[:40])


if __name__ == "__main__":
    main()
