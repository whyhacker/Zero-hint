# The Warlord's Estate — writeup

**Category:** pwn / Insane · **libc:** GNU libc 2.39-0ubuntu8.7 · Full RELRO, PIE, NX, canary, seccomp (open/read/write only)

## The bug
`redraw` calls a reader (`0x1730`) that reads exactly `size` bytes into the chunk, then writes
`buf[size] = 0` — a classic **off-by-one NULL** (poison-null-byte). It triggers when the request
size equals the chunk's usable size (e.g. `0x508` for a `0x510` chunk), so the NULL lands on the
next chunk's size-field low byte. `claim` uses a *safe* line reader (no overflow); `raze` frees and
NULLs the slot (no naive UAF/double-free); `survey` = `write(1, ptr, size)` (leak primitive).

Globals: `ptrs[]@0x40e0`, `sizes[]@0x4060`, 16 slots, size ≤ 0x1000.

## Chain
1. **libc leak** — a large chunk (`>0x410`) freed goes to the unsorted bin; re-`claim`ing it (sending
   no data) leaves the `main_arena` fd/bk in the returned user data → `survey` leaks it.
   `libc = leak - 0x203b20`.
2. **heap leak** — a `0x90` chunk freed into an empty tcache bin stores `next = 0 ^ (chunk>>12)`;
   re-`claim` + `survey` leaks `heap>>12` (defeats safe-linking).
3. **overlap** — poison-null-byte (how2heap 2.39 largebin variant) built with the known heap base,
   so the fd/bk edits use full pointers instead of the 2-byte/alignment trick. Backward
   consolidation unlinks a fake chunk and yields a freed chunk overlapping a live slot (`slot3`).
4. **arbitrary alloc** — carve four `0x100` tcache chunks inside `slot3`'s window; `slot3` can rewrite
   the head chunk's `fd`. glibc 2.39 gates the tcache fast-path on `counts[idx] > 0`, so we keep the
   count ≥ 2 and re-free the scratch chunk after each op to keep a controllable head. Safe-linking is
   handled with the heap leak. (`tcache_get` sets `key = *(ptr+8) = 0`, so targets are chosen with an
   offset that keeps that write harmless.)
5. **stack write → ORW ROP** — read libc `environ` for a stack leak; `redraw_rbp = environ - 0x268`
   (stable). Poison a chunk onto `redraw`'s own frame at `redraw_rbp-0x10` and `redraw` it: the reader
   writes the chain so the ROP sits at `redraw_rbp+8` (offset `0x18`). When `redraw` returns the chain
   runs `open("flag.txt") / read / write`.

Note: glibc 2.39 has **no executable `pop rdx; ret`** (they live below the exec segment), so `rdx` is
set with `mov edx,0x80 ; pop rbx ; pop r12 ; pop rbp ; ret` (`0x9a4d0`).

## Run
```sh
python3 exploit.py            # local, against the shipped libc via the loader
python3 exploit.py <HOST>     # remote (port 5000)
```
Local: 10/10 reliable.

## Remote note
`0x268` is the `environ → redraw_rbp` distance for the local invocation; it depends on argv/env, so a
different remote launcher may shift it. It can be made launcher-independent by scanning the stack for
`__libc_start_call_main+X` (libc+0x2a1ca here, i.e. `main`'s saved return) and computing
`redraw_rbp = main_rbp - 0x130`.
