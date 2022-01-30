#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the Beginner picoMini 2022 challenge ncme.

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

    io = remote('saturn.picoctf.net', 57688)

    return io



def main():
    '''Return the flag.
    '''

    with conn() as io:

        flag = io.recvlineS()
        log.success(f'The flag is: {flag}')
        return flag


if __name__ == '__main__':
    main()
