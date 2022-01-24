#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the 247CTF challenge watch-and-learn.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *
import re

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

URL = 'https://www.youtube.com/c/247CTF/about'

def conn():
    '''Download the webpage. Returns the temporary file.
    '''

    filename = tempfile.mktemp()
    res = wget(URL, filename, timeout=30)

    return open(filename, 'rb')


def main():
    '''Return the flag.
    '''

    # Get a handle on the file.
    with conn() as io:
        # Go down each line in the file.
        for line in io.readlines():
            # Check if the flag pattern occurs in any of them.
            # [0-9A-Fa-f]+ searched for any number of hex characters.
            match = re.search(r'247CTF{[0-9A-Fa-f]+}', line.decode())

            if match:
                flag = match.group()
                log.success(f'The flag is {flag}.')
                return flag

        # If we've got down all of the lines and haven't found the flag,
        # raise an error.
        raise ValueError('Could not find the flag.')


if __name__ == '__main__':
    main()
