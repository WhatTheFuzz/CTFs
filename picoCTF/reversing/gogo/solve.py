#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the picoCTF challenge gogo.

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
from pwn import *

exe = ELF("./enter_password")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

# This location is where the hardcoded string we are xoring is stored.
ADDR_STRING1 = 0x0810fe00

def get_string1():
    '''Get the hardcoded string from the string table.
    '''
    return exe.read(ADDR_STRING1, count=32)

def get_string2():
    '''
    See writeup for details.
    '''
    return '861836f13e3d627dfa375bdb8389214e'.encode()

def get_password():
    '''xor the two strings.
    Returns the result as a byte string.
    '''
    a = get_string1()
    log.info(f'The first string is: {a}')
    b = get_string2()
    log.info(f'The second string is: {b}')

    # XOR the two strings together to get the result.
    return bytes([a[i] ^ b[i] for i in range(len(a))])
    # Later learned we can use xor(a, b); keeping this here for learning purposes though!

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('mercury.picoctf.net', 35862)

    else:
        io = process([exe.path])

    return io

def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Get the password, which is just the XOR of the two strings.
        password = get_password()
        log.success(f'The password is: {password.decode()}')

        io.sendlineafter(b'Enter Password: ', password)

        # Send the unhashed key. This was found with crackstation.net and entering
        # the string2 into the program. This yielded the string 'goldfish'.
        io.sendlineafter(b'What is the unhashed key?\n', b'goldfish')

        flag = io.recvlineS().strip('Flag is:  ')

        log.success(f'The flag is: {flag}')
        return flag


if __name__ == '__main__':
    main()


