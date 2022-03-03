#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the 247CTF challenge The Encrypted Password.

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

exe = ELF('./encrypted_password')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def connection():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        conn = remote('addr', 4141)

    else:
        conn = process([exe.path])

    return conn


def main():
    '''Return the flag.
    '''

    with connection() as conn:

        conn.interactive()


if __name__ == '__main__':
    main()
