#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the 247CTF challenge Socket Challenges.

This script can be used in the following manner:
python3 ./solve.py

Modify the address and port to connect to the challenge. This will change for
each individual and may change after each 24 hours. This script will not work
for you; you must modify the address and port.

Returns:
    The flag to solve the challenge.
"""

from pwn import *

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

ADDR = '0a96a528e666aa90.247ctf.com'
PORT = 50035

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = remote(ADDR, PORT)
    return io


def main():
    '''Return the flag.
    '''

    with conn() as io:

        flag = io.recvlineS()
        log.success(f'The flag is: {flag}')


if __name__ == '__main__':
    main()
