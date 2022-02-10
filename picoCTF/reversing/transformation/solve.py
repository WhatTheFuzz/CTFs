#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the picoCTF challenge Transformation.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''
    return open('./enc', 'rb')

def main():
    '''Return the flag.
    '''

    with conn() as io:
        line = io.readline().decode()
        log.info(f'The file enc contains the text: {line}')

        flag = line.encode('utf-16-be')
        log.success(f'The flag is: {flag}')
        return flag


if __name__ == '__main__':
    main()
