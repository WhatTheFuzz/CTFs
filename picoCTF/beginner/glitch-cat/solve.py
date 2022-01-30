#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the Beginner picoMini 2022 challenge Glitch Cat.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

context.log_level = 'info'

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = remote('saturn.picoctf.net', 52026)

    return io



def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Get the line.
        line = io.recvuntil(b'\r\n')
        # Interpret the line as Python code.
        flag = eval(line.decode())

        log.success(f'The flag is: {flag}.')


if __name__ == '__main__':
    main()
