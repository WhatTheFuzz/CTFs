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

import re
import r2pipe
from pwn import *

exe = ELF("./the_more_the_merrier")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('addr', 4141)

    else:
        io = process([exe.path])

    return io

def get_string():
    '''Use radare2 to get the string from the binary.'''
    r = r2pipe.open(exe.path)
    # radare2 is dumb, but this will dump all of the strings in the data section.
    # It will look something like this:
    # [Strings]
    # nth paddr      vaddr      len size section type    string
    # ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――
    # 0   0x000006e8 0x000006e8 40  164  .rodata utf32le 247CTF{6df215eb3cc73407267031a15b0ab36c}
    # 1   0x0000078c 0x0000078c 21  22   .rodata ascii   Nothing to see here..
    data = r.cmd('iz')

    # Regex to nab the flag.
    flag = re.search(r'247CTF\{.*}', data).group(0)
    return flag



def main():
    '''Return the flag.
    '''

    flag = get_string()
    log.success(f'The flag is: {flag}')


if __name__ == '__main__':
    main()
