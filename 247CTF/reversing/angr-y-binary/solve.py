#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the 247CTF challenge angr-y binary.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
'''

import angr
import claripy
from pwn import *

exe = ELF('./angr-y_binary')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

# scanf(%20s)
KEY_LEN = 20
ADDR_NO_FLAG = 0x08048609
ADDR_PRINT_FLAG = 0x080485ea


def connection():
    '''Establish the connection to the process, local or remote.
    '''
    # This address probably won't work for you, as it is different for each
    # person each 24 hours.
    if args.get('REMOTE'):
        conn = remote('tcp://d8ed15688217915a.247ctf.com', 50457)

    else:
        conn = process([exe.path])

    return conn


def get_password():
    '''Get the password for the executable to print the flag.
    '''
    # Create an angr project.
    project = angr.Project(exe.path)

    # We can tell from Ghidra that the user input comes from `scanf(%20s)`.
    # Thus we know the size of our input.
    flag_chars = [claripy.BVS(f'flag_char_{i}', 8) for i in range(KEY_LEN)]
    flag = claripy.Concat(*flag_chars)

    # Create the initial state and pass in the symbolic input.
    initial_state = project.factory.full_init_state(
        args=[exe.path], add_options=angr.options.unicorn, stdin=flag)

    # Constrain the characters to be not null and not newline characters.
    for j in flag_chars:
        initial_state.solver.add(j != int.from_bytes(b'\x00', 'little'))
        initial_state.solver.add(j != int.from_bytes(b'\n', 'little'))

    # Create the simulation manager and explore the binary.
    sm = project.factory.simgr(initial_state)

    # Explore the binary.
    sm.explore(find=ADDR_PRINT_FLAG, avoid=[ADDR_NO_FLAG])

    # Check if a solution was found.
    if sm.found:
        sol_state = sm.found[0]
        password = sol_state.solver.eval(flag, cast_to=bytes)
        log.success(f'The password is: {password}')
        return password
    log.error('Password not found.')
    return None


def main():
    '''Return the flag.
    '''

    # Get the password with angr.
    password = get_password()

    # Pass the password to the binary to get the flag.
    with connection() as conn:
        conn.sendlineafter(b'Enter a valid password:\n', password)
        flag = conn.recvline_startswith(b'247CTF{')
        log.success(f'The flag is: {flag}')

        assert flag == b'247CTF{a3bbb9d2e648841d99e1cf4535a92945}', 'Received incorrect flag.'

        return flag


if __name__ == '__main__':
    main()
