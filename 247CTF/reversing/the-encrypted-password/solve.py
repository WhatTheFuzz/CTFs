#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the 247CTF challenge The Encrypted Password.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
'''

from pwn import *

exe = ELF('./encrypted_password')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

GDB_SCRIPT = '''
br strcmp@plt
run
'''

def connection():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        conn = remote('addr', 4141)

    else:
        conn = process([exe.path])

    return conn

def get_password():
    '''Return the password.
    '''

    with connection() as conn:

        # Attach to the process.
        pid, dbg = gdb.attach(conn, GDB_SCRIPT, api=True)

        conn.wait(1)

        conn.sendline('test')



def main():
    '''Return the flag.
    '''

    with connection() as conn:

        conn.interactive()


if __name__ == '__main__':
    get_password()
