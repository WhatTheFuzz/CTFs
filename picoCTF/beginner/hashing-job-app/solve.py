#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the Beginner picoMini 2022 challenge HashingJobApp.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

import re
from hashlib import md5
from pwn import *

context.log_level = 'info'

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = remote('saturn.picoctf.net', 65352)

    return io



def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Loop through all of the answers.
        while  b'picoCTF' not in (line := io.recvline()):
            if b'Please md5 hash' in line:
                # Get everything in between the single quotes.
                substring = re.search("'.*'", line.decode()).group(0).strip("'")

                log.info(f'The substring is: {substring}.')

                # Get the md5sum of the substring.
                md5sum = md5(substring.encode()).hexdigest()
                log.info(f'The md5sum is: {md5sum}.')

                # Send the `md5sum` to the program.
                io.sendlineafter(b'Answer:', md5sum.encode())

        flag = line.decode()
        log.success(f'The flag is: {flag}')


if __name__ == '__main__':
    main()
