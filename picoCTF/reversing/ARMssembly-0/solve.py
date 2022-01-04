#!/usr/bin/env python3

"""
WhatTheFuzz's submission for the picoCTF challenge ARMssembly-0.

This script can be used in the following manner:
python3 ./solve.py

Args:
    None

Returns:
    The flag to solve the challenge.
"""

from pwn import *
import docker

context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

IMAGE_NAME = 'armssembly-0'

def build_and_run_container():
    '''For whatever reason, the Fedora dnf package for the aarch64 cross-compiler
    doesn't currently support building userland binaries. So we use Ubuntu instead.

    $ dnf info gcc-aarch64-linux-gnu
    Only building kernels is currently supported.  Support for cross-building
    user space programs is not currently provided as that would massively multiply
    the number of packages.

    Returns the result of running the executable in the container as an integer.
    '''
    client = docker.from_env()
    # Build the image from the Dockerfile in this directory.
    client.images.build(path='.', tag=IMAGE_NAME, quiet=False)

    # Run the container, the two numbers are provided by the challenge.
    stdout = client.containers.run(IMAGE_NAME, "/chall 1765227561 1830628817").decode('utf-8')

    # The program prints something to stdout in the form of:
    # Result: 69
    # This block tries to parse the string and return just the number as an int.
    try:
        num = stdout.split('Result: ')[1]
        num = int(num.strip('\n'))
        log.success(f'Result: {num}')
        return num
    except ValueError as e:
        print('Error: {}'.format(e))
        raise

def time_func(func):
    '''Time the main function.
    '''

    start = time.time()
    func()
    end = time.time()

    log.success(f'Time: {end - start}')

def main():
    '''Return the flag.
    '''

    # The prompt specifies that the flag should be in the form of picoCTF{...}
    # where ... is the result of the executable with the arguments
    # 1765227561 1830628817 in hex, lowercase, no 0x, and 32 bits.
    result = build_and_run_container()
    # This is tricky to read, but we escape the curly braces by using two of them.
    log.success(f'The flag is: picoCTF{{{format(result, "x")}}}')

if __name__ == '__main__':
    time_func(main)
