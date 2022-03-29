#!/usr/bin/env python3
'''
WhatTheFuzz's submission for the picoCTF challenge wizardlike.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    None. Writes a file names flag_art.txt to the current directory.
    The flag is written as ascii art.
'''

from pwn import *

exe = ELF('./game')
# Found dynamically with gdb.
exe.address = 0x555555554000

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

NUM_COLUMNS = 100
NUM_ROWS = 100
ARRAY_SIZE = NUM_COLUMNS * NUM_ROWS
# See function `main`. The program checks to see what floor we're currently on
# and prints the floor artwork for the respective floor.
FLOORS = {
    1: 0x55555555b740,
    2: 0x55555555de60,
    3: 0x555555560580,
    4: 0x555555562ca0,
    5: 0x5555555653c0,
    6: 0x555555567ae0,
    7: 0x55555556a200,
    8: 0x55555556c920,
    9: 0x55555556f040,
    10: 0x555555571760
}


def generate_ascii_art():
    art = []
    for floor, addr in FLOORS.items():
        # Read the ascii art into a buffer.
        floor_art = exe.read(addr, ARRAY_SIZE)
        # Split the lines to fit into the number of columns.
        art += [
            floor_art[i:i + NUM_COLUMNS]
            for i in range(0, len(floor_art), NUM_COLUMNS)
        ]

    return art


def main():
    '''Return the flag.
    '''

    # Generate the ascii art.
    art = generate_ascii_art()

    # Log it to a file.
    with open('flag_art.txt', 'wb') as f:
        for line in art:
            f.write(line + b'\n')


if __name__ == '__main__':
    main()
