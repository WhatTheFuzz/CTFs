#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the <CTF> challenge <name>.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./kappa")
hook = ELF("./hook.so")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('addr', 4141)

    else:
        # LD_PRELOAD to prevent `sleep` from being called.
        io = process([exe.path], env = {'LD_PRELOAD': hook.path})

    return io



def main():
    '''Return the flag.
    '''

    with conn() as io:

        io.interactive()


if __name__ == '__main__':
    main()
