#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the 247TF challenge Tips and Tricks.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

ADDR = '406ecb300aa92668.247ctf.com'
PORT = 50455

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = remote(ADDR, PORT)

    return io



def main():
    '''Return the flag.
    '''

    with conn() as io:

        line = ''

        while True:
            # Search for the line that is the question.
            while '?' not in line:
                line = io.recvuntilS('\r\n', drop=True)

                # Check if we have the flag this time.
                if '247CTF{' in line:
                    log.success(f'The flag is: {line}')
                    return line

            # This line is asking a math question, parse out all of the
            # alphabetical characters.
            line = ''.join(i for i in line if i.isdigit() or i in ['+', '-', '*', '/'])

            log.debug(f'Line to evaluate: {line}')
            log.debug(f'Answer: {eval(line)}')

            # Send the answer back to the server.
            io.send(str(eval(line)).encode() + b'\r\n')


if __name__ == '__main__':
    main()
